
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

#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sqlite3.h>
#include "dnsd.h"

enum sql_stmt_indices {
	st_name,

	st_last = st_name
};

static const char *sql_stmt_text[] = {
	/* st_name */
	"select labels.name, rrs.* from labels, rrs where "
	"labels.id = rrs.domain and "
	"rrs.domain in "
	"(select labels.id from labels where labels.name = ?)",
};

static sqlite3_stmt *prep_stmts[st_last + 1];
static sqlite3 *db;

void backend_init(void)
{
	unsigned int i;
	int rc;

	rc = sqlite3_open(db_fn, &db);
	if (rc != SQLITE_OK) {
		syslog(LOG_ERR, "sqlite3_open failed");
		exit(1);
	}

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

void backend_query(const struct dnsq *q, struct dnsres *res)
{
	int rc;
	unsigned int idx, rows = 0;

	idx = st_name;

	rc = sqlite3_bind_text(prep_stmts[idx], 1,
			      q->name, strlen(q->name),
			      SQLITE_STATIC);
	g_assert(rc == SQLITE_OK);

	while (1) {
		struct backend_rr rr;

		/* execute SQL query */
		rc = sqlite3_step(prep_stmts[idx]);
		if (rc == SQLITE_DONE || rc == SQLITE_BUSY)
			break;
		g_assert(rc == SQLITE_ROW);

		rows++;

		memset(&rr, 0, sizeof(rr));
		rr.domain = sqlite3_column_text(prep_stmts[idx], 0);
		/* skip suffix, column #1 */
		rr.type = sqlite3_column_int(prep_stmts[idx], 2);
		rr.class = sqlite3_column_int(prep_stmts[idx], 3);
		rr.ttl = sqlite3_column_int(prep_stmts[idx], 4);
		rr.rdata = sqlite3_column_blob(prep_stmts[idx], 5);
		rr.rdata_len = sqlite3_column_bytes(prep_stmts[idx], 5);

		/* filter out non-matching classes and types */
		if (q->class != rr.class)
			continue;
		if ((q->type != qtype_all) && (q->type != rr.type))
			continue;

		dns_push_rr(res, &rr);
	}

	rc = sqlite3_reset(prep_stmts[idx]);
	g_assert(rc == SQLITE_OK);

	/* no data found for given domain name */
	if (rows == 0)
		dns_set_rcode(res, rcode_nxdomain);
}

