
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

int backend_query(struct dnsres *res, const struct dns_msg_hdr *hdr)
{
	return -1;
}

