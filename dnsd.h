#ifndef __DNSD_H__
#define __DNSD_H__

#include <stdint.h>
#include <glib.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

enum {
	max_label_len		= 63,
	initial_suffix_alloc	= 512,
};

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

	struct dns_label	*first_label;
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
};


/* backend.c */
extern void backend_init(void);
extern void backend_exit(void);
extern void backend_query(void *data, void *user_data);

/* dns.c */
extern void dnsres_free(struct dnsres *res);
extern struct dnsres *dns_message(const char *buf, unsigned int buflen);

/* socket.c */
extern void init_net(void);

#endif /* __DNSD_H__ */
