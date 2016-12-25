#if defined(PATH_VECTOR_INCLUDED)

#include <stdio.h>
#include <string.h>
#include <sys/types.h>  
#include <sys/socket.h>
#include <unistd.h>
//#include <sys/ioctl.h>
//#include <netinet/in.h>
//#include <net/if.h>
//#include <arpa/inet.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>    // isdigit and friends
#include <stddef.h>                             /* offsetof */
#include <net/if_arp.h>
//#include <linux/if_ether.h>
#include <setjmp.h>
#include <sys/stat.h> 
#include <fcntl.h>
#include "pv_manager.h"
#include "pv_api.h"
#include "log.h"
#include "pv_main.h"

#define CONSOLE_MSG_LEN 256

extern int as_num;


void pv_error_console(const char *str)
{
	char buf[CONSOLE_MSG_LEN+1] = {0};

	strncpy(buf, str, CONSOLE_MSG_LEN);
	fprintf(stdout, "%s\n", buf);
	
	return;
}  

/* Update PV socket send buffer size */
void pv_update_sock_send_buffer_size (int fd)
{
	
	int size = PV_SOCKET_SNDBUF_SIZE;
	int optval;
	socklen_t optlen = sizeof(optval);

	if (getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &optval, &optlen) < 0)
	{
		PRINT_MESSAGE("%s : %d : getsockopt of SO_SNDBUF failed %s \n", __func__, __LINE__, safe_strerror(errno));
		return;
	}
	if (optval < size)
	{
		if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)) < 0)
		{
			PRINT_MESSAGE("%s : %d : Couldn't increase send buffer: %s \n", __func__, __LINE__, safe_strerror(errno));
		}
	}
	
}

int open_rte_file(FILE **out)
{
	FILE *stream = NULL;
    
	switch(as_num)
	{
		case 1: 
		stream = fopen (PV_RTABLE_FILENAME_AS1, "w");
		break;
		
		case 2: 
		stream = fopen (PV_RTABLE_FILENAME_AS2, "w");
		break;
		
		case 3: 
		stream = fopen (PV_RTABLE_FILENAME_AS3, "w");
		break;
		
		case 4: 
		stream = fopen (PV_RTABLE_FILENAME_AS4, "w");
		break;
		
		case 5: 
		stream = fopen (PV_RTABLE_FILENAME_AS5, "w");
		break;
		
	}
	
	if (!stream)
	{  
		PRINT_MESSAGE("%s : %d : Unable to open RTE file\n", __func__, __LINE__);
		return PV_FAIL;
	}
	*out = stream;
	
	return PV_SUCCESS;
}	

int close_rte_file(FILE *stream)
{
	
	
	rewind(stream);
	
	if (fclose (stream) == EOF)
		PRINT_MESSAGE("%s : %d : Unable to close RTE file\n", __func__, __LINE__);
	
	
	return PV_SUCCESS;
}
	
#endif
