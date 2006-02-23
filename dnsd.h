
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

#ifndef __DNSD_H__
#define __DNSD_H__

#include <stdint.h>
#include <glib.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

enum {
	max_label_len		= 63,
	initial_suffix_alloc	= 512,

	qtype_all		= 255,

	rcode_nxdomain		= 3,
	rcode_notimpl		= 4,

	op_query		= 0,
};

struct dns_msg_hdr {
	uint16_t		id;
	unsigned char		opts[2];
	uint16_t		n_q;
	uint16_t		n_ans;
	uint16_t		n_auth;
	uint16_t		n_add;
};

enum dns_hdr_bits {
	hdr_response		= 1 << 7,
	hdr_auth		= 1 << 2,
	hdr_req_recur		= 1 << 0,
	hdr_opcode_mask		= 0x78,
	hdr_opcode_shift	= 3,
};

struct dnsq {
	GList			*labels;
	unsigned int		type;
	unsigned int		class;

	char			*first_label;
	char			*suffix;
	unsigned int		suffix_alloc;
};

struct dnsres {
	char			*buf;
	unsigned int		buflen;
	unsigned int		alloc_len;
	unsigned int		hdrq_len;
	GList			*queries;
	int			query_rc;

	unsigned int		n_answers;
};

struct backend_rr {
	const unsigned char	*name;
	const unsigned char	*domain_name;
	int			type;
	int			class;
	int			ttl;
	const void		*rdata;
	unsigned int		rdata_len;
};

/* backend.c */
extern void backend_init(void);
extern void backend_exit(void);
extern void backend_query(void *data, void *user_data);

/* dns.c */
extern void dnsres_free(struct dnsres *res);
extern struct dnsres *dns_message(const char *buf, unsigned int buflen);
extern void dns_push_rr(struct dnsres *res, const struct backend_rr *rr);
extern void dns_set_rcode(struct dnsres *res, unsigned int code);

/* socket.c */
extern void init_net(void);

/* main.c */
extern int dns_port;
extern char db_fn[];

#endif /* __DNSD_H__ */
