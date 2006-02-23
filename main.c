
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
#include <string.h>
#include <glib.h>
#include "dnsd.h"

char db_fn[4096] = "dns.db";
int dns_port = 9953;

static void show_usage(const char *prog)
{
	fprintf(stderr, "usage: %s [options]\n"
		"options:\n"
		"  -p PORT		bind to port PORT\n"
		"  -f FILE		use sqlite database FILE\n",
		prog);
	exit(1);
}

int main (int argc, char *argv[])
{
	GMainLoop *loop;
	int opt;

	while ((opt = getopt(argc, argv, "hf:p:")) != -1) {
		switch (opt) {
			case 'p':
				if (atoi(optarg) > 0 &&
				    atoi(optarg) < 65536)
					dns_port = atoi(optarg);
				break;
			case 'f':
				strcpy(db_fn, optarg);
				break;
			default:
				show_usage(argv[0]);
				break;
		}
	}

	loop = g_main_loop_new(NULL, FALSE);
	g_assert(loop != NULL);

	init_net();
	backend_init();

	g_main_loop_run(loop);

	backend_exit();

	return 0;
}

