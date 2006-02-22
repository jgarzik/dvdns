
#include <string.h>
#include <glib.h>
#include "dnsd.h"

static void dns_finalize(struct dnsres *res)
{
	struct dns_msg_hdr *hdr;

	hdr = (struct dns_msg_hdr *) res->buf;
	hdr->n_ans = g_htons(res->n_answers);
	hdr->opts |= g_htons(hdr_auth);
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
	uint16_t rdlen;

	dns_push_label(res, (const char *) rr->name);

	labels = g_strsplit((const gchar *) rr->domain_name, ".", 0);
	for (idx = 0; labels[idx]; idx++)
		dns_push_label(res, labels[idx]);
	g_strfreev(labels);

	ttl = g_htonl(rr->ttl);
	rdlen = g_htons(rr->rdata_len);

	dns_push_bytes(res, rr->type, 2);
	dns_push_bytes(res, rr->class, 2);
	dns_push_bytes(res, &ttl, 4);
	dns_push_bytes(res, &rdlen, 2);
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
	g_free(q->suffix);
	g_free(q);
}

void dnsres_free(struct dnsres *res)
{
	g_list_foreach(res->queries, dnsres_free_q, NULL);
	g_list_free(res->queries);
	g_free(res->buf);
	g_free(res);
}

static void dnsq_append_label(struct dnsq *q, const char *buf, unsigned int buflen)
{
	char *label;

	/* create label record */
	label = g_utf8_strdown(buf, buflen);

	/* add label to question's list of labels */
	q->labels = g_list_append(q->labels, label);

	/* maintain first_label / suffix */
	if (!q->first_label)
		q->first_label = label;
	else {
		if (!q->suffix) {
			q->suffix = g_malloc(initial_suffix_alloc);
			q->suffix[0] = 0;
			q->suffix_alloc = initial_suffix_alloc;
		}
		else if ((buflen+1) > (q->suffix_alloc - strlen(q->suffix))) {
			q->suffix_alloc *= 2;
			q->suffix = g_realloc(q->suffix, 
				q->suffix_alloc);
		}

		if (q->suffix[0] != 0)
			strcat(q->suffix, ".");
		strcat(q->suffix, label);
	}
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

		q = g_new0(struct dnsq, 1);
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
		
		memcpy(q->type, ibuf, 2);
		memcpy(q->class, ibuf + 2, 2);
		q->type[2] = 0;
		q->class[2] = 0;

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
	uint16_t opts, o_opts;
	const char *ibuf;
	unsigned int ibuflen;
	int rc;

	/* allocate result struct */
	res = g_new0(struct dnsres, 1);
	g_assert(res != NULL);

	ibuf = buf;
	ibuflen = buflen;

	/* bail, if packet smaller than dns header */
	if (buflen < sizeof(*hdr))
		goto err_out;

	hdr = (const struct dns_msg_hdr *) buf;
	opts = g_ntohs(hdr->opts);

	ibuf += sizeof(*hdr);
	ibuflen -= sizeof(*hdr);

	/* if this is a response packet, just return NULL */
	if (opts & hdr_response)
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
	o_opts = opts & (hdr_req_recur | hdr_opcode_mask);
	o_opts |= hdr_response;
	ohdr->opts = g_htons(o_opts);
	ohdr->n_ans = 0;
	ohdr->n_auth = 0;
	ohdr->n_add = 0;

	g_list_foreach(res->queries, backend_query, res);
	if (res->query_rc != 0)			/* query failed */
		goto err_out;

	dns_finalize(res);

	return res;

err_out:
	dnsres_free(res);
	return NULL;
}

