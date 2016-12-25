#if defined(PATH_VECTOR_INCLUDED)

#include <zebra.h>

#include "ipc_config.h"
#include "pv_main.h"
#include "getopt.h"
#include "thread.h"
#include "privs.h"
#include "sigevent.h"
#include "pv_api.h"
#include "pv_main.h"
#include "pv_manager.h"

struct thread_master *master;

zebra_capabilities_t _caps_p [] = 
{
	ZCAP_NET_RAW,
	ZCAP_BIND
};

struct zebra_privs_t pv_privs =
{
#if defined(IPC_USER)
	.user = IPC_USER,
#endif
#if defined IPC_GROUP
	.group = IPC_GROUP,
#endif
	.caps_p = _caps_p,
	.cap_num_p = 2,
	.cap_num_i = 0
};

const char *pid_file ;

int main(int argc, char *argv[])
{
	
	int daemon_mode = 0;
	struct thread thread;
	char buffer[512];
	int as_number = 0;

	umask(0027);
	

	if( argc == 2 ) {
		
		as_number = atoi(argv[1]);
	}
	else if( argc > 2 ) {
		PRINT_MESSAGE("%s : %d : Too many arguments supplied.  \n", __func__, __LINE__);
		return;
	}
	else {
		PRINT_MESSAGE("%s : %d : One argument AS number expected.  \n", __func__, __LINE__);
		return;
	}

	master = thread_master_create();
	zprivs_init(&pv_privs);

	if (daemon_mode && daemon (0, 0) < 0)
	{
		PRINT_MESSAGE("%s : %d : PATH VECTOR daemon failed: %s \n", __func__, __LINE__, strerror(errno));
		exit (1);
	}

	switch(as_number)
	{
		case 1:
		 pid_file = PV_DAEMON_PID_FILE_AS1;
		 break;
		 
		case 2:
		 pid_file = PV_DAEMON_PID_FILE_AS2;
		 break;
		 
		case 3:
		 pid_file = PV_DAEMON_PID_FILE_AS3;
		 break;
		 
		case 4:
		 pid_file = PV_DAEMON_PID_FILE_AS4;
		 break;
		 
		case 5:
		 pid_file = PV_DAEMON_PID_FILE_AS5;
		 break;
	}
	pid_output(pid_file);
	
	if(!wr_pv_init(as_number))
		exit(1);
	
	while(thread_fetch(master, &thread))
		thread_call (&thread);

	
	return PV_SUCCESS;
}
#else
int main(void)
{
	
	return 0;
}
#endif
