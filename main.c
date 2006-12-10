
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

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <glib.h>
#include <gnet.h>
#include <argp.h>
#include "dnsd.h"

#define PROGRAM_NAME "dvdnsd"

char db_fn[4096] = "dns.db";
char pid_fn[4096] = "dvdnsd.pid";
int dns_port = 9953;
static int foreground;
struct dns_server_stats srvstat;

static const char doc[] =
PROGRAM_NAME " - authoritative DNS server";

static struct argp_option options[] = {
	{ "database", 'f', "FILE", 0,
	  "use sqlite database FILE" },
	{ "foreground", 'F', NULL, 0,
	  "Run in foreground, do not fork" },
	{ "port", 'p', "PORT", 0,
	  "bind to port PORT" },
	{ "pid", 'P', "FILE", 0,
	  "Write daemon process id to FILE" },

	{ }
};

static error_t parse_opt (int key, char *arg, struct argp_state *state);
static const struct argp argp = { options, parse_opt, NULL, doc };

static error_t parse_opt (int key, char *arg, struct argp_state *state)
{
	switch(key) {
	case 'f':
		strcpy(db_fn, arg);
		break;
	case 'F':
		foreground = 1;
		break;
	case 'p':
		if (atoi(arg) > 0 && atoi(arg) < 65536)
			dns_port = atoi(arg);
		else {
			fprintf(stderr, "invalid DNS port %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'P':
		strcpy(pid_fn, arg);
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);	/* too many args */
		break;
	case ARGP_KEY_END:
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static void syslogerr(const char *prefix)
{
	syslog(LOG_ERR, "%s: %s", prefix, strerror(errno));
}

static void write_pid_file(void)
{
	char str[32], *s;
	size_t bytes;

	sprintf(str, "%u\n", getpid());
	s = str;
	bytes = strlen(s);

	int fd = open(pid_fn, O_WRONLY | O_CREAT | O_EXCL, 0666);
	if (fd < 0) {
		syslogerr("open pid");
		exit(1);
	}

	while (bytes > 0) {
		ssize_t rc = write(fd, s, bytes);
		if (rc < 0) {
			syslogerr("write pid");
			exit(1);
		}

		bytes -= rc;
		s += rc;
	}

	if (close(fd) < 0)
		syslogerr("close pid");
}

int main (int argc, char *argv[])
{
	GMainLoop *loop;
	error_t rc;

	rc = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (rc) {
		fprintf(stderr, "argp_parse failed: %s\n", strerror(rc));
		return 1;
	}

	memset(&srvstat, 0, sizeof(srvstat));

	openlog("dvdnsd", LOG_PID, LOG_LOCAL3);

	if ((!foreground) && (daemon(1, 0) < 0)) {
		syslogerr("daemon");
		return 1;
	}

	write_pid_file();

	gnet_init();

	loop = g_main_loop_new(NULL, FALSE);
	g_assert(loop != NULL);

	init_net();
	backend_init();
	dns_init();

	syslog(LOG_INFO, "initialized");

	g_main_loop_run(loop);

	backend_exit();

	return 0;
}

