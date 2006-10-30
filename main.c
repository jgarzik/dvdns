
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
#include "dnsd.h"

char db_fn[4096] = "dns.db";
char pid_fn[4096] = "dvdnsd.pid";
int dns_port = 9953;
static int foreground;

static void show_usage(const char *prog)
{
	fprintf(stderr, "usage: %s [options]\n"
		"options:\n"
		"  -f FILE		use sqlite database FILE\n"
		"  -p PORT		bind to port PORT\n"
		"  -P FILE		Write daemon process id to FILE\n",
		prog);
	exit(1);
}

static void parse_cmdline(int argc, char **argv)
{
	int opt;

	while ((opt = getopt(argc, argv, "hf:Fp:P:")) != -1) {
		switch (opt) {
			case 'f':
				strcpy(db_fn, optarg);
				break;
			case 'F':
				foreground = 1;
				break;
			case 'p':
				if (atoi(optarg) > 0 &&
				    atoi(optarg) < 65536)
					dns_port = atoi(optarg);
				else {
					fprintf(stderr, "invalid DNS port %s\n",
						optarg);
					exit(1);
				}
				break;
			case 'P':
				strcpy(pid_fn, optarg);
				break;
			default:
				show_usage(argv[0]);
				exit(1);
		}
	}
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

	parse_cmdline(argc, argv);

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

	syslog(LOG_INFO, "initialized");

	g_main_loop_run(loop);

	backend_exit();

	return 0;
}

