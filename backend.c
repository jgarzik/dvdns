
#include <string.h>
#include <sqlite3.h>
#include "dnsd.h"

enum sql_stmt_indices {
	st_name,
	st_name_type,

	st_last = st_name_type
};

static const char *sql_stmt_text[] = {
	/* st_name */
	"select labels.name, rrs.* from labels, rrs where "
	"rrs.name = ? and "
	"rrs.suffix in "
	"(select labels.id from labels where labels.name = ?)",

	/* st_name_type */
	"select labels.name, rrs.* from labels, rrs where "
	"rrs.name = ? and "
	"rrs.type = ? and "
	"rrs.suffix in "
	"(select labels.id from labels where labels.name = ?)"
};

static sqlite3_stmt *prep_stmts[st_last + 1];
static sqlite3 *db;

void backend_init(void)
{
	unsigned int i;
	int rc;

	rc = sqlite3_open("dns.db", &db);
	g_assert(rc == SQLITE_OK);

	for (i = 0; i <= st_last; i++) {
		const char *dummy;

		rc = sqlite3_prepare(db, sql_stmt_text[i],
				     strlen(sql_stmt_text[i]),
				     &prep_stmts[i], &dummy);
		g_assert(rc == SQLITE_OK);
	}
}

void backend_exit(void)
{
	unsigned int i;
	int rc;

	for (i = 0; i <= st_last; i++)
		sqlite3_finalize(prep_stmts[i]);

	rc = sqlite3_close(db);
	g_assert(rc == SQLITE_OK);
}

void backend_query(void *data, void *user_data)
{
	struct dnsq *q = data;
	struct dnsres *res = user_data;
	int rc;
	unsigned int idx;

	if (q->type[0] == '*') {
		idx = st_name;

		rc = sqlite3_bind_text(prep_stmts[idx], 1,
				      q->first_label->buf,
				      q->first_label->buflen,
				      SQLITE_STATIC);
		g_assert(rc == SQLITE_OK);

		rc = sqlite3_bind_text(prep_stmts[idx], 2,
				      q->suffix, strlen(q->suffix),
				      SQLITE_STATIC);
		g_assert(rc == SQLITE_OK);
	} else {
		idx = st_name_type;

		rc = sqlite3_bind_text(prep_stmts[idx], 1,
				      q->first_label->buf,
				      q->first_label->buflen,
				      SQLITE_STATIC);
		g_assert(rc == SQLITE_OK);

		rc = sqlite3_bind_text(prep_stmts[idx], 2,
				      q->type, strlen(q->type),
				      SQLITE_STATIC);
		g_assert(rc == SQLITE_OK);

		rc = sqlite3_bind_text(prep_stmts[idx], 3,
				      q->suffix, strlen(q->suffix),
				      SQLITE_STATIC);
		g_assert(rc == SQLITE_OK);
	}

	while (1) {
		struct backend_rr rr;

		/* execute SQL query */
		rc = sqlite3_step(prep_stmts[idx]);
		if (rc == SQLITE_DONE || rc == SQLITE_BUSY)
			break;
		g_assert(rc == SQLITE_ROW);

		memset(&rr, 0, sizeof(rr));
		rr.domain_name = sqlite3_column_text(prep_stmts[idx], 0);
		rr.name = sqlite3_column_text(prep_stmts[idx], 1);
		/* skip suffix, column #2 */
		rr.type = sqlite3_column_text(prep_stmts[idx], 3);
		rr.class = sqlite3_column_text(prep_stmts[idx], 4);
		rr.ttl = sqlite3_column_int(prep_stmts[idx], 5);
		rr.rdata = sqlite3_column_blob(prep_stmts[idx], 6);
		rr.rdata_len = sqlite3_column_bytes(prep_stmts[idx], 6);

		dns_push_rr(res, &rr);
	}

	(void) res;
}

