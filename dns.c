
/*
 * Copyright 2006 Jeff Garzik
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.  If not, write to
 * the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#include <string.h>
#include <glib.h>
#include "dnsd.h"

void dns_set_rcode(struct dnsres *res, unsigned int code)
{
	struct dns_msg_hdr *hdr;

	hdr = (struct dns_msg_hdr *) res->buf;
	hdr->opts[1] = code & 0x0f;
}

static void dns_finalize(struct dnsres *res)
{
	struct dns_msg_hdr *hdr;

	hdr = (struct dns_msg_hdr *) res->buf;
	hdr->n_ans = g_htons(res->n_answers);
	hdr->opts[0] |= hdr_auth;
}

static void dns_push_bytes(struct dnsres *res, const void *buf,
			   unsigned int buflen)
{
	if ((res->alloc_len - res->buflen) < buflen) {
		res->alloc_len = (res->alloc_len * 2) + buflen;
		res->buf = g_realloc(res->buf, res->alloc_len);
	}

	memcpy(res->buf + res->buflen, buf, buflen);
	res->buflen += buflen;
}

static void dns_push_label(struct dnsres *res, const char *str)
{
	uint8_t len = strlen(str);

	g_assert(len <= 63);

	dns_push_bytes(res, &len, 1);
	dns_push_bytes(res, str, len);
}

void dns_push_rr(struct dnsres *res, const struct backend_rr *rr)
{
	char **labels;
	unsigned int idx;
	uint32_t ttl;
	uint16_t tmp;
	uint8_t zero8 = 0;

	labels = g_strsplit((const gchar *) rr->domain, ".", 0);
	for (idx = 0; labels[idx]; idx++)
		dns_push_label(res, labels[idx]);
	g_strfreev(labels);

	dns_push_bytes(res, &zero8, 1);

	tmp = g_htons(rr->type);
	dns_push_bytes(res, &tmp, 2);

	tmp = g_htons(rr->class);
	dns_push_bytes(res, &tmp, 2);

	ttl = g_htonl(rr->ttl);
	dns_push_bytes(res, &ttl, 4);

	tmp = g_htons(rr->rdata_len);
	dns_push_bytes(res, &tmp, 2);
	dns_push_bytes(res, rr->rdata, rr->rdata_len);

	res->n_answers++;
}

static void list_free_ent(void *data, void *user_data)
{
	g_free(data);
}

static void dnsres_free_q(void *data, void *user_data)
{
	struct dnsq *q = data;

	g_list_foreach(q->labels, list_free_ent, NULL);
	g_list_free(q->labels);
	g_free(q->name);
	g_slice_free(struct dnsq, q);
}

void dnsres_free(struct dnsres *res)
{
	g_list_foreach(res->queries, dnsres_free_q, NULL);
	g_list_free(res->queries);
	g_free(res->buf);
	g_slice_free(struct dnsres, res);
}

static struct dnsres *dnsres_alloc(void)
{
	struct dnsres *res = g_slice_new0(struct dnsres);
	return res;
}

static void dnsq_append_label(struct dnsq *q, const char *buf, unsigned int buflen)
{
	char *label;

	/* create label record */
	label = g_utf8_strdown(buf, buflen);

	/* add label to question's list of labels */
	q->labels = g_list_append(q->labels, label);

	if (!q->name) {
		q->name = g_malloc(initial_name_alloc);
		q->name[0] = 0;
		q->name_alloc = initial_name_alloc;
	}
	else if ((buflen+1) > (q->name_alloc - strlen(q->name))) {
		q->name_alloc *= 2;
		q->name = g_realloc(q->name, q->name_alloc);
	}

	if (q->name[0] != 0)
		strcat(q->name, ".");
	strcat(q->name, label);
}

static int dns_read_questions(struct dnsres *res, const struct dns_msg_hdr *hdr,
			      const char **ibuf_io, unsigned int *ibuflen_io)
{
	unsigned int i;
	const char *ibuf = *ibuf_io;
	unsigned int ibuflen = *ibuflen_io;
	int rc = 0;

	for (i = 0; i < g_ntohs(hdr->n_q); i++) {
		struct dnsq *q;
		uint16_t *tmpi;

		q = g_slice_new0(struct dnsq);
		g_assert(q != NULL);

		/* read list of labels */
		while (1) {
			unsigned int label_len;

			if (ibuflen == 0)
				goto err_out;

			/* get label length */
			label_len = *ibuf;
			ibuf++;
			ibuflen--;

			/* if label length zero, list terminates */
			if (label_len == 0)
				break;

			/* FIXME: pointer compression */
			if (label_len > ibuflen || label_len > max_label_len)
				goto err_out;

			/* copy label */
			dnsq_append_label(q, ibuf, label_len);

			ibuf += label_len;
			ibuflen -= label_len;
		}

		/* read type, class */
		if (ibuflen < 4)
			goto err_out;

		tmpi = (uint16_t *) ibuf;
		q->type = g_ntohs(*tmpi);

		tmpi = (uint16_t *) (ibuf + 2);
		q->class = g_ntohs(*tmpi);

		ibuf += 4;
		ibuflen -= 4;

		/* add to list of queries */
		res->queries = g_list_append(res->queries, q);
	}

out:
	*ibuf_io = ibuf;
	*ibuflen_io = ibuflen;
	return rc;

err_out:
	rc = -1;
	goto out;
}

struct dnsres *dns_message(const char *buf, unsigned int buflen)
{
	const struct dns_msg_hdr *hdr;
	struct dns_msg_hdr *ohdr;
	struct dnsres *res;
	char *obuf;
	const char *ibuf;
	unsigned int ibuflen, opcode;
	int rc;

	/* allocate result struct */
	res = dnsres_alloc();
	if (!res)
		return NULL;

	ibuf = buf;
	ibuflen = buflen;

	/* bail, if packet smaller than dns header */
	if (buflen < sizeof(*hdr))
		goto err_out;

	hdr = (const struct dns_msg_hdr *) buf;

	ibuf += sizeof(*hdr);
	ibuflen -= sizeof(*hdr);

	/* if this is a response packet, just return NULL (no resp to client) */
	if (hdr->opts[0] & hdr_response)
		goto err_out;

	/* read list of questions */
	rc = dns_read_questions(res, hdr, &ibuf, &ibuflen);
	if (rc != 0)			/* invalid input */
		goto err_out;

	/* note length of hdr + query section */
	res->hdrq_len = buflen - ibuflen;

	/* allocate output buffer */
	res->alloc_len = MAX(4 * 1024, buflen);
	obuf = res->buf = g_malloc0(res->alloc_len);
	g_assert(obuf != NULL);

	/* copy hdr + query section into response packet */
	ohdr = (struct dns_msg_hdr *) obuf;
	memcpy(obuf, buf, res->hdrq_len);
	res->buflen = res->hdrq_len;

	/* sanitize response header */
	ohdr->opts[0] =
		hdr_response |
		(hdr->opts[0] & hdr_opcode_mask) |
		(hdr->opts[0] & hdr_req_recur);
	ohdr->n_ans = 0;
	ohdr->n_auth = 0;
	ohdr->n_add = 0;

	opcode = (hdr->opts[0] & hdr_opcode_mask) >> hdr_opcode_shift;
	switch (opcode) {
		case op_query:
			g_list_foreach(res->queries, backend_query, res);
			if (res->query_rc != 0)		/* query failed */
				goto err_out;
			break;

		default:
			dns_set_rcode(res, rcode_notimpl);
			break;
	}

	dns_finalize(res);

	return res;

err_out:
	dnsres_free(res);
	return NULL;
}

