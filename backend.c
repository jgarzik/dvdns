
#include <sqlite3.h>
#include "dnsd.h"

static sqlite3 *db;

void backend_init(void)
{
	int rc = sqlite3_open("dns.db", &db);
	g_assert(rc == SQLITE_OK);
}

void backend_exit(void)
{
	int rc = sqlite3_close(db);
	g_assert(rc == SQLITE_OK);
}

void backend_query(void *data, void *user_data)
{
	struct dnsq *q = data;
	struct dnsres *res = user_data;

	(void) q;
	(void) res;
}

