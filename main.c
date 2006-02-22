
#include <glib.h>
#include "dnsd.h"

int main (int argc, char *argv[])
{
	GMainLoop *loop;

	loop = g_main_loop_new(NULL, FALSE);
	g_assert(loop != NULL);

	init_net();
	backend_init();

	g_main_loop_run(loop);

	backend_exit();

	return 0;
}

