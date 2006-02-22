#ifndef __DNSD_H__
#define __DNSD_H__

#include <stdint.h>
#include <glib.h>

struct dns_msg_hdr {
	uint16_t		id;
	uint16_t		opts;
	uint16_t		n_q;
	uint16_t		n_ans;
	uint16_t		n_auth;
	uint16_t		n_add;
};

enum dns_hdr_bits {
	hdr_response		= 1 << 0,
	hdr_req_recur		= 1 << 7,
	hdr_opcode_mask		= 0x1e,
};

struct dns_label {
	unsigned int		buflen;
	char			buf[0];
};

struct dnsq {
	GList			*labels;
	char			type[3];
	char			class[3];
};

struct dnsres {
	char			*buf;
	unsigned int		buflen;
	unsigned int		alloc_len;
	unsigned int		hdrq_len;
	GList			*queries;
};


/* backend.c */
extern void backend_init(void);
extern void backend_exit(void);
extern int backend_query(struct dnsres *res, const struct dns_msg_hdr *hdr);

/* dns.c */
extern void dnsres_free(struct dnsres *res);
extern struct dnsres *dns_message(const char *buf, unsigned int buflen);


#endif /* __DNSD_H__ */
