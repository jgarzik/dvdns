
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

#include <glib.h>
#include <gnet.h>
#include "dnsd.h"

enum client_state {
	idle,
	msglen,
	msg,
};

struct client {
	GConn			 *conn;
	enum client_state	state;
};

static GUdpSocket *udpsock;


static void udp_message(GUdpSocket *sock, const GInetAddr *src,
			const char *buf, unsigned int buflen)
{
	struct dnsres *res = dns_message(buf, buflen);

	srvstat.udp_q++;

	if (res) {
		gnet_udp_socket_send(sock, res->buf, res->buflen, src);
		dnsres_free(res);
	}
}

static gboolean udp_rx (GIOChannel *source, GIOCondition condition,
                                             void *data)
{
	char buf[2048];
	int bytes;
	GInetAddr *src = NULL;

	bytes = gnet_udp_socket_receive(udpsock, buf, sizeof(buf), &src);
	g_assert (bytes > 0);
	g_assert (src != NULL);

	udp_message(udpsock, src, buf, bytes);

	return TRUE; /* poll again */
}

static void tcp_message(struct client *cli, const char *buf, unsigned int buflen)
{
	struct dnsres *res = dns_message(buf, buflen);

	srvstat.tcp_q++;

	if (res) {
		uint16_t msglen = g_htons(res->buflen);
		gnet_conn_write(cli->conn, (gchar *) &msglen, 2);
		gnet_conn_write(cli->conn, res->buf, res->buflen);
		dnsres_free(res);
	}
}

static void cli_close(struct client *cli)
{
	gnet_conn_unref(cli->conn);
	g_slice_free(struct client, cli);
}

static void tcp_conn (GConn *conn, GConnEvent *event, void *user_data)
{
	struct client *cli = user_data;

	switch (event->type) {
	case GNET_CONN_ERROR:
	case GNET_CONN_CLOSE:
		cli_close(cli);
		break;

	case GNET_CONN_WRITE:
		break;

	case GNET_CONN_READ:
		if (cli->state == msglen) {
			unsigned short *s = (unsigned short *) event->buffer;
			int msglen = g_ntohs(*s);

			gnet_conn_readn(cli->conn, msglen);
			cli->state = msg;
		}
		else if (cli->state == msg) {
			tcp_message(cli, event->buffer, event->length);

			gnet_conn_readn(cli->conn, 2);
			cli->state = msglen;
		}
		break;

	default:
		/* do nothing */
		break;
	}
}

static void tcp_accept (GServer *server, GConn *client, void *data)
{
	struct client *cli;

	g_assert(client != NULL);	/* socket error */

	cli = g_slice_new0(struct client);
	g_assert(cli != NULL);

	cli->conn = client;
	cli->state = idle;

	gnet_conn_set_callback(client, tcp_conn, cli);

	gnet_conn_readn(client, 2);
	cli->state = msglen;
}

void init_net(void)
{
	GIOChannel *udpchan;
	GServer *tcpsrv;

	udpsock = gnet_udp_socket_new_with_port (dns_port);
	g_assert(udpsock != NULL);

	udpchan = gnet_udp_socket_get_io_channel (udpsock);
	g_assert(udpchan != NULL);

	g_io_add_watch(udpchan, G_IO_IN, udp_rx, NULL);

	tcpsrv = gnet_server_new(NULL, dns_port, tcp_accept, NULL);
	g_assert(tcpsrv != NULL);
}

