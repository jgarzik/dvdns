
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
#include <time.h>
#include <glib.h>
#include "dnsd.h"

enum {
	MSG_CACHE_EXPIRE		= 60,
};

static GQueue		*msg_expire_q;
static GHashTable	*msg_cache;
static time_t		current_time;


/* "djb2"-derived hash function */
static unsigned long blob_hash(unsigned long hash, const void *_buf, size_t buflen)
{
	const unsigned char *buf = _buf;
	int c;

	while (buflen > 0) {
		c = *buf++;
		buflen--;

		hash = ((hash << 5) + hash) ^ c; /* hash * 33 ^ c */
	}

	return hash;
}

static void msg_cache_expire(void)
{
	struct dnsres *res;

	while (1) {
		res = g_queue_peek_head(msg_expire_q);
		if (!res)
			return;
		if (current_time < res->mc_expire)
			return;

		g_queue_pop_head(msg_expire_q);
		g_hash_table_remove(msg_cache, (gpointer) res->hash);
	}
}

static struct dnsres *msg_cache_lookup(const char *buf, unsigned int buflen,
				       int *expired, unsigned long *hash_out)
{
	struct dnsres *res;
	unsigned long hash;

	*expired = 0;

	hash = blob_hash(BLOB_HASH_INIT, buf, buflen);
	hash = blob_hash(hash, &buflen, sizeof(buflen));
	*hash_out = hash;

	res = g_hash_table_lookup(msg_cache, (gpointer) hash);
	if (!res)
		return NULL;

	if (current_time < res->mc_expire)
		return res;
	
	msg_cache_expire();
	*expired = 1;
	return NULL;
}

static void msg_cache_add(unsigned long hash, struct dnsres *res)
{
	g_hash_table_insert(msg_cache, (gpointer) hash, res);
	g_queue_push_tail(msg_expire_q, res);

}

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

static void dns_res_grow(struct dnsres *res, unsigned int buflen)
{
	size_t new_size = res->alloc_len;
	void *mem;

	do {
		new_size = new_size << 1;
	} while ((new_size - res->buflen) < buflen);

	mem = g_slice_alloc(new_size);
	memcpy(mem, res->buf, res->alloc_len);
	g_slice_free1(res->alloc_len, res->buf);

	res->buf = mem;
	res->alloc_len = new_size;
}

static void dns_push_bytes(struct dnsres *res, const void *buf,
			   unsigned int buflen)
{
	if ((res->alloc_len - res->buflen) < buflen)
		dns_res_grow(res, buflen);

	memcpy(res->buf + res->buflen, buf, buflen);
	res->buflen += buflen;
}

void dns_push_rr(struct dnsres *res, const struct backend_rr *rr)
{
	const unsigned char *s, *accum;
	size_t accum_len;
	uint32_t ttl;
	uint16_t tmp;
	uint8_t zero8 = 0;

	accum_len = 0;
	accum = s = rr->domain;
	while (1) {
		if (*s == '.' || *s == 0) {
			if (accum_len) {
				uint8_t len = accum_len;
				g_assert(len <= 63);
				dns_push_bytes(res, &len, 1);
				dns_push_bytes(res, accum, accum_len);
			}

			if (*s == 0)
				break;

			accum = s + 1;
			accum_len = 0;
		} else
			accum_len++;

		s++;
	}

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
	g_slice_free1(q->name_alloc, q->name);
	g_slice_free(struct dnsq, q);
}

static void dnsres_free(struct dnsres *res)
{
	g_list_foreach(res->queries, dnsres_free_q, NULL);
	g_list_free(res->queries);
	g_slice_free1(res->alloc_len, res->buf);
	g_slice_free(struct dnsres, res);
}

void dnsres_unref(struct dnsres *res)
{
	g_assert(res->n_refs > 0);

	res->n_refs--;
	if (!res->n_refs)
		dnsres_free(res);
}

static struct dnsres *dnsres_alloc(void)
{
	struct dnsres *res = g_slice_new0(struct dnsres);
	if (res)
		res->n_refs = 1;
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
		q->name = g_slice_alloc(initial_name_alloc);
		q->name[0] = 0;
		q->name_alloc = initial_name_alloc;
	}
	else if ((buflen+1) > (q->name_alloc - strlen(q->name))) {
		void *mem;
		size_t new_size = q->name_alloc << 1;

		/* simulate g_realloc with slices */
		mem = g_slice_alloc(new_size);
		memcpy(mem, q->name, q->name_alloc);
		g_slice_free1(q->name_alloc, q->name);

		q->name = mem;
		q->name_alloc = new_size;
	}

	if (q->name[0] != 0)
		strcat(q->name, ".");
	strcat(q->name, label);
}

enum {
	max_ptr_stack		= 32,
};

struct ptr_stack {
	unsigned int		len;
	unsigned int		ptr[max_ptr_stack];
};

static int in_ptr_history(struct ptr_stack *ps, unsigned int ptr)
{
	unsigned int len = ps->len;
	unsigned int i;

	for (i = 0; i < len; i++)
		if (ps->ptr[i] == ptr)
			return 1;

	if (len == max_ptr_stack)
		return 1;

	ps->ptr[len] = ptr;
	ps->len++;

	return 0;
}

static int dns_parse_label(struct dnsq *q, const char *label,
			   const char *msg, unsigned int msg_len)
{
	unsigned int idx = label - msg;
	unsigned int free, saved_len = 0, ptr_chasing = 0;
	const char *p;
	struct ptr_stack ps;

	ps.len = 0;

	/* read list of labels */
next_ptr:
	p = &msg[idx];
	free = msg_len - idx;
	while (1) {
		unsigned int label_len, label_flags;

		if (free == 0)
			goto err_out;

		/* get label length */
		label_len = *p;
		p++;
		free--;

		/* move bits 7-6 to label_flags */
		label_flags = label_len & 0xc0;
		label_len &= 0x3f;

		/* bits 01 and 10 are reserved / not handled */
		if (label_flags == 0x80 || label_flags == 0x40)
			goto err_out;

		/* pointer compression (offset-based labels) */
		if (label_flags == 0xc0) {
			if (free == 0)
				goto err_out;

			idx = (label_len << 8) | (*p);
			p++;
			free--;

			if (idx >= msg_len)
				goto err_out;
			if (in_ptr_history(&ps, idx))
				goto err_out;

			if (!ptr_chasing) {
				ptr_chasing = 1;
				saved_len = p - label;
			}

			goto next_ptr;
		}

		/* normal label */
		else {
			/* verify free space */
			if (label_len > free)
				goto err_out;

			/* if label length zero, list terminates */
			if (label_len == 0)
				break;

			/* copy label */
			dnsq_append_label(q, p, label_len);

			p += label_len;
			free -= label_len;
		}
	}

	if (ptr_chasing)
		return saved_len;
	return p - label;

err_out:
	return -1;
}

static int dns_parse_msg(struct dnsres *res, const struct dns_msg_hdr *hdr,
			 const char *msg, unsigned int msg_len)
{
	unsigned int i;
	const char *ibuf = msg;
	unsigned int ibuflen = msg_len;
	unsigned int n_q = g_ntohs(hdr->n_q);
	int rc = 0;

	ibuf += sizeof(*hdr);
	ibuflen -= sizeof(*hdr);

	for (i = 0; i < n_q; i++) {
		struct dnsq *q;
		uint16_t tmpi;
		int label_len;

		q = g_slice_new0(struct dnsq);
		g_assert(q != NULL);

		/*
		 * read label, with pointer decompression
		 */
		label_len = dns_parse_label(q, ibuf, msg, msg_len);
		if (label_len < 0)
			goto err_out;

		ibuf += label_len;
		ibuflen -= label_len;

		/*
		 * read type, class
		 */
		if (ibuflen < 4)
			goto err_out;

		memcpy(&tmpi, ibuf, 2);
		q->type = g_ntohs(tmpi);

		memcpy(&tmpi, ibuf + 2, 2);
		q->class = g_ntohs(tmpi);

		ibuf += 4;
		ibuflen -= 4;

		/* add to list of queries */
		res->queries = g_list_append(res->queries, q);
	}

out:
	/* note length of hdr + query section */
	res->hdrq_len = msg_len - ibuflen;
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
	unsigned int opcode;
	unsigned long hash;
	int rc, expired;

	current_time = time(NULL);

	/* look up raw bytes in message cache */
	res = msg_cache_lookup(buf, buflen, &expired, &hash);
	if (res) {
		srvstat.mc_hit++;
		return dnsres_ref(res);
	}

	srvstat.mc_miss++;

	/* allocate result struct */
	res = dnsres_alloc();
	if (!res)
		return NULL;

	res->mc_expire = current_time + MSG_CACHE_EXPIRE;

	/* bail, if packet smaller than dns header */
	if (buflen < sizeof(*hdr))
		goto err_out;

	hdr = (const struct dns_msg_hdr *) buf;

	/* if this is a response packet, just return NULL (no resp to client) */
	if (hdr->opts[0] & hdr_response)
		goto err_out;

	/* read list of questions */
	rc = dns_parse_msg(res, hdr, buf, buflen);
	if (rc != 0)			/* invalid input */
		goto err_out;

	/* allocate output buffer */
	res->alloc_len = MAX(1024, buflen);
	obuf = res->buf = g_slice_alloc(res->alloc_len);
	g_assert(obuf != NULL);

	/* copy hdr + query section into response packet */
	memcpy(obuf, buf, res->hdrq_len);
	res->buflen = res->hdrq_len;

	/* sanitize response header */
	ohdr = (struct dns_msg_hdr *) obuf;
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
			g_list_foreach(res->queries,
				       (GFunc) backend_query, res);
			if (res->query_rc != 0)		/* query failed */
				goto err_out;
			break;

		default:
			dns_set_rcode(res, rcode_notimpl);
			break;
	}

	dns_finalize(res);

	/* add to message cache */
	if (!expired)
		msg_cache_expire();
	msg_cache_add(hash, dnsres_ref(res));

	return res;

err_out:
	dnsres_unref(res);
	return NULL;
}

void dns_init(void)
{
	msg_cache = g_hash_table_new_full(g_direct_hash, g_direct_equal,
					  NULL, (GDestroyNotify) dnsres_unref);
	g_assert(msg_cache != NULL);

	msg_expire_q = g_queue_new();
	g_assert(msg_expire_q != NULL);
}

