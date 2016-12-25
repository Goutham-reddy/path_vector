#if defined(PATH_VECTOR_INCLUDED)

#include <sys/utsname.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h> 
//#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <setjmp.h>
#include <unistd.h>
#include <sys/wait.h>
#include <ctype.h>
#include <errno.h>
#include <errno.h>
#include <sys/types.h>


//#include <zebra.h>
#include "prefix.h"
#include "thread.h"
#include "buffer.h"
#include "stream.h"
//#include "command.h"
#include "sockunion.h"
#include "sockopt.h"
#include "network.h"
//#include "memory.h"
#include "filter.h"
#include "routemap.h"
#include "str.h"
#include "log.h"
#include "plist.h"
#include "linklist.h"
//#include "workqueue.h"
#include "table.h"
#include "pv_main.h"
#include "pv_manager.h"
#include "pv_api.h"
#include "privs.h"

pv_srvconf_params *pv_srvconf_params_1;
pv_srvconf pv_srvconf_1;
pv_message_metadata pv_message_metadata_self ; /** Clean up not done **/
int as_num;
extern struct thread_master *master;
extern struct zebra_privs_t pv_privs;

int wr_pv_init(int as_number)
{
	as_num = as_number;

	pv_srvconf_params_1 = malloc(sizeof (pv_srvconf_params));
	if(!pv_srvconf_params_1)
	{
		PRINT_MESSAGE("%s : %d : pv_srvconf_params Memory allocation failed \n", __func__, __LINE__);
		return PV_FAIL;
	}	
	memset(pv_srvconf_params_1, 0 , sizeof(pv_srvconf_params));

	pv_srvconf_params_1->accepted_peer_sockets = list_new ();
	pv_srvconf_params_1->connect_peer_sockets = list_new ();

	pv_srvconf_params_1->pv_route_table_link = malloc(sizeof (pv_routing_table_link));
	if(!pv_srvconf_params_1->pv_route_table_link)
	{
		PRINT_MESSAGE("%s : %d : pv_routing_table_link Memory allocation failed\n", __func__, __LINE__);
		return PV_FAIL;
	}	
	memset(pv_srvconf_params_1->pv_route_table_link, 0 , sizeof(pv_routing_table_link));

	pv_srvconf_params_1->pv_route_table_link->route_table_column = route_table_init ();
	pv_srvconf_params_1->pv_route_table_link->routing_table_row = list_new ();

	setup_connections_to_neighbour(as_number);

	pv_build_self_metadata();


	if(pv_listener() == PV_FAIL)
	{
		PRINT_MESSAGE("%s : %d : pv_listener() error\n", __func__, __LINE__);
		return PV_FAIL;
	}

	return PV_SUCCESS;
}

int setup_connections_to_neighbour(unsigned char current_as_no)
{


	switch(current_as_no)
	{
		case 1:

			pv_srvconf_1.pv_current_ipAddress = (unsigned int)inet_addr(AS1_IP); /* Network Byte order */ 
			pv_srvconf_1.pv_first_neighbour_ipAddress = (unsigned int)inet_addr(AS1_NEIGHBOUR_1_IP); /* Network Byte order */ 
			pv_srvconf_1.pv_second_neighbour_ipAddress = (unsigned int)inet_addr(AS1_NEIGHBOUR_2_IP); /* Network Byte order */ 
			pv_srvconf_1.pv_currrent_Port = (unsigned short)AS1_PORT;
			pv_srvconf_1.pv_first_neighbour_Port = (unsigned short)AS1_NEIGHBOUR_1_PORT;
			pv_srvconf_1.pv_second_neighbourPort = (unsigned short)AS1_NEIGHBOUR_2_PORT;
			pv_srvconf_1.pv_current_AS_number = AS1_NUMBER;
			pv_srvconf_1.pv_first_neighbour_AS_number = AS2_NUMBER;
			pv_srvconf_1.pv_second_neighbour_AS_number = AS5_NUMBER;

			break;
		case 2:
			pv_srvconf_1.pv_current_ipAddress = (unsigned int)inet_addr(AS2_IP); /* Network Byte order */ 
			pv_srvconf_1.pv_first_neighbour_ipAddress = (unsigned int)inet_addr(AS2_NEIGHBOUR_1_IP); /* Network Byte order */ 
			pv_srvconf_1.pv_second_neighbour_ipAddress = (unsigned int)inet_addr(AS2_NEIGHBOUR_2_IP); /* Network Byte order */ 
			pv_srvconf_1.pv_currrent_Port = (unsigned short)AS2_PORT;
			pv_srvconf_1.pv_first_neighbour_Port = (unsigned short)AS2_NEIGHBOUR_1_PORT;
			pv_srvconf_1.pv_second_neighbourPort = (unsigned short)AS2_NEIGHBOUR_2_PORT;
			pv_srvconf_1.pv_current_AS_number = AS2_NUMBER;
			pv_srvconf_1.pv_first_neighbour_AS_number = AS1_NUMBER;
			pv_srvconf_1.pv_second_neighbour_AS_number = AS3_NUMBER;
			break;
		case 3:
			pv_srvconf_1.pv_current_ipAddress = (unsigned int)inet_addr(AS3_IP); /* Network Byte order */ 
			pv_srvconf_1.pv_first_neighbour_ipAddress = (unsigned int)inet_addr(AS3_NEIGHBOUR_1_IP); /* Network Byte order */ 
			pv_srvconf_1.pv_second_neighbour_ipAddress = (unsigned int)inet_addr(AS3_NEIGHBOUR_2_IP); /* Network Byte order */ 
			pv_srvconf_1.pv_currrent_Port = (unsigned short)AS3_PORT;
			pv_srvconf_1.pv_first_neighbour_Port = (unsigned short)AS3_NEIGHBOUR_1_PORT;
			pv_srvconf_1.pv_second_neighbourPort = (unsigned short)AS3_NEIGHBOUR_2_PORT;
			pv_srvconf_1.pv_current_AS_number = AS3_NUMBER;
			pv_srvconf_1.pv_first_neighbour_AS_number = AS2_NUMBER;
			pv_srvconf_1.pv_second_neighbour_AS_number = AS4_NUMBER;
			break;
		case 4:
			pv_srvconf_1.pv_current_ipAddress = (unsigned int)inet_addr(AS4_IP); /* Network Byte order */ 
			pv_srvconf_1.pv_first_neighbour_ipAddress = (unsigned int)inet_addr(AS4_NEIGHBOUR_1_IP); /* Network Byte order */ 
			pv_srvconf_1.pv_second_neighbour_ipAddress = (unsigned int)inet_addr(AS4_NEIGHBOUR_2_IP); /* Network Byte order */ 
			pv_srvconf_1.pv_currrent_Port = (unsigned short)AS4_PORT;
			pv_srvconf_1.pv_first_neighbour_Port = (unsigned short)AS4_NEIGHBOUR_1_PORT;
			pv_srvconf_1.pv_second_neighbourPort = (unsigned short)AS4_NEIGHBOUR_2_PORT;
			pv_srvconf_1.pv_current_AS_number = AS4_NUMBER;
			pv_srvconf_1.pv_first_neighbour_AS_number = AS5_NUMBER;
			pv_srvconf_1.pv_second_neighbour_AS_number = AS3_NUMBER;
			break;
		case 5:
			pv_srvconf_1.pv_current_ipAddress = (unsigned int)inet_addr(AS5_IP); /* Network Byte order */ 
			pv_srvconf_1.pv_first_neighbour_ipAddress = (unsigned int)inet_addr(AS5_NEIGHBOUR_1_IP); /* Network Byte order */ 
			pv_srvconf_1.pv_second_neighbour_ipAddress = (unsigned int)inet_addr(AS5_NEIGHBOUR_2_IP); /* Network Byte order */ 
			pv_srvconf_1.pv_currrent_Port = (unsigned short)AS5_PORT;
			pv_srvconf_1.pv_first_neighbour_Port = (unsigned short)AS5_NEIGHBOUR_1_PORT;
			pv_srvconf_1.pv_second_neighbourPort = (unsigned short)AS5_NEIGHBOUR_2_PORT;
			pv_srvconf_1.pv_current_AS_number = AS5_NUMBER;
			pv_srvconf_1.pv_first_neighbour_AS_number = AS1_NUMBER;
			pv_srvconf_1.pv_second_neighbour_AS_number = AS4_NUMBER;
			break;
		default:
			PRINT_MESSAGE("%s : %d : Invalid AS number specified\n", __func__, __LINE__);
			break;

	}


	return PV_SUCCESS;
}

int pv_event(enum pv_event event, int fd_sock, void *extra)
{
	int msec_time = 2000;
	int sec = 2000;
	pv_peer_accept_info *pv_peer_accept_info = NULL;
	pv_peer_connect_info *pv_peer_connect_info = NULL;


	switch (event)
	{
		/* Notification to read a discover packet from the socket */ 
		case PV_LISTENER_READ:

			pv_srvconf_params_1->hPV_ListenerThread = thread_add_read (master, pv_accept, NULL, fd_sock);
			break;

		case PV_ACCEPT_PEER_READ_MESSAGE:

			pv_peer_accept_info = extra;
			pv_peer_accept_info->thread = thread_add_read (master, pv_read_packet, pv_peer_accept_info, fd_sock);
			break;

		case PV_CLIENT_CONNECT_EVENT:

			pv_peer_connect_info = extra;
			pv_peer_connect_info->thread = thread_add_event (master, pv_open_connection_to_neighbours, pv_peer_connect_info, pv_peer_connect_info->neigh_no);
			break;

		case PV_CLIENT_CONNECT_TIMER:

			pv_peer_connect_info = extra;
			pv_peer_connect_info->thread = thread_add_timer_msec (master, pv_open_connection_to_neighbours, pv_peer_connect_info, msec_time);
			break;

		case PV_MY_UPDATE_TIMER:

			pv_srvconf_params_1->hPVMyUpdate = thread_add_timer_msec (master, pv_adv_self_prefix, NULL, msec_time);
			break;			

		case PV_PRINT_RT_TABLE_TIMER:

			pv_srvconf_params_1->hPV_rt_table_print = thread_add_timer_msec (master, pv_print_route_table_to_file, NULL, sec);
			break;
		default:
			break;
	}


	return PV_SUCCESS;
}

int pv_listener ()
{
	struct sockaddr_in  addr = {0};
	int sock = -1;
	int ret, en;
	pv_peer_connect_info *pv_peer_connect_info_1 = NULL;
	pv_peer_connect_info *pv_peer_connect_info_2 = NULL;

	addr.sin_family = AF_INET;
	addr.sin_port = htons(pv_srvconf_1.pv_currrent_Port);
	addr.sin_addr.s_addr = pv_srvconf_1.pv_current_ipAddress;
	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (sock < 0)
	{
		close(sock);
		PRINT_MESSAGE("%s : %d : Listening socket creation error.\n", __func__, __LINE__);
		return PV_FAIL;
	}

	sockopt_reuseaddr (sock);
	sockopt_reuseport (sock);

	if (pv_privs.change (ZPRIVS_RAISE))
		PRINT_MESSAGE("%s : %d : Listening socket error. cannot raise previledges \n", __func__, __LINE__);

	ret = bind (sock, (struct sockaddr*)&addr, sizeof(struct sockaddr_in));
	en = errno;
	if (pv_privs.change (ZPRIVS_LOWER))
		PRINT_MESSAGE("%s : %d : Listening socket error. cannot lower previledges \n", __func__, __LINE__);

	if (ret < 0)
	{
		PRINT_MESSAGE("%s : %d : bind: %s \n", __func__, __LINE__, safe_strerror (en));
		return ret;
	}

	ret = listen (sock, 3);
	if (ret < 0)
	{
		PRINT_MESSAGE("%s : %d : listen: %s \n", __func__, __LINE__, safe_strerror (en));
		return ret;
	}

	pv_srvconf_params_1->listener_socket_id = sock;

	/* Connenction to neighbours */
	pv_peer_connect_info_1 = malloc(sizeof(pv_peer_connect_info));
	if(!pv_peer_connect_info_1)
	{
		PRINT_MESSAGE("%s : %d : pv_peer_connect_info_1 Memory allocation failed\n", __func__, __LINE__);
		return PV_FAIL;
	}	
	memset(pv_peer_connect_info_1, 0, sizeof(pv_peer_connect_info));
	pv_peer_connect_info_1->neigh_no = 1;

	pv_peer_connect_info_2 = malloc(sizeof(pv_peer_connect_info));
	if(!pv_peer_connect_info_2)
	{
		PRINT_MESSAGE("%s : %d : pv_peer_connect_info_2 Memory allocation failed\n", __func__, __LINE__);
		return PV_FAIL;
	}	
	memset(pv_peer_connect_info_2, 0, sizeof(pv_peer_connect_info));
	pv_peer_connect_info_2->neigh_no = 2;

	pv_event(PV_CLIENT_CONNECT_EVENT, -1, pv_peer_connect_info_1);
	pv_event(PV_CLIENT_CONNECT_EVENT, -1, pv_peer_connect_info_2);

	/* Advertise my AS to peers */
	pv_event(PV_MY_UPDATE_TIMER, -1, NULL);

	/* Pull data if any */
	pv_event(PV_LISTENER_READ, sock, NULL); // calls pv_accept on read

	pv_event(PV_PRINT_RT_TABLE_TIMER, -1, NULL); 

	return PV_SUCCESS;
}

/* Accept PV connection from neighbour. */
int pv_accept (struct thread *thread)
{
	int pv_sock;
	int accept_sock;
	union sockunion su = {0};
	pv_peer_accept_info *pv_peer_accept_info = NULL;
	struct in_addr   sin_addr = {0};

	/* Register accept thread. */
	accept_sock = THREAD_FD (thread);
	if (accept_sock < 0)
	{
		PRINT_MESSAGE("%s : %d : Error: accept_sock is nevative value %d \n", __func__, __LINE__, accept_sock);
		return PV_FAIL;
	}

	pv_event(PV_LISTENER_READ, accept_sock, NULL);// calls pv_accept on read

	/* Accept client connection. Accept file is created here*/
	pv_sock = sockunion_accept (accept_sock, &su);
	if (pv_sock < 0)
	{
		PRINT_MESSAGE("%s : %d : [Error] PV socket accept failed (%s) \n", __func__, __LINE__, safe_strerror (errno));
		return -1;
	}

	memcpy(&sin_addr, &(su.sin.sin_addr), sizeof(struct in_addr));
	PRINT_MESSAGE("%s : %d : New** connection from the neighbour %s \n", __func__, __LINE__, inet_ntoa(sin_addr));

	set_nonblocking (pv_sock);

	/* Set socket send buffer size */
	pv_update_sock_send_buffer_size(pv_sock);

	pv_peer_accept_info = malloc(sizeof(pv_peer_accept_info));
	if(!pv_peer_accept_info)
	{
		PRINT_MESSAGE("%s : %d : pv_peer_accept_info Memory allocation failed\n", __func__, __LINE__);
		return PV_FAIL;
	}	
	memset(pv_peer_accept_info, 0, sizeof(pv_peer_accept_info));

	pv_peer_accept_info->fd = pv_sock;
	pv_peer_accept_info->packet_data_in = stream_new (PV_MAX_PACKET_SIZE);
	memcpy(&(pv_peer_accept_info->su), &su, sizeof(union sockunion));
	listnode_add (pv_srvconf_params_1->accepted_peer_sockets, pv_peer_accept_info);

	pv_event(PV_ACCEPT_PEER_READ_MESSAGE, pv_sock, pv_peer_accept_info); // calls pv_read_packet when actual data is in

	return PV_SUCCESS;
}

/* Read PV TCP Stream. */
int pv_read_packet (struct thread *thread)
{


	pv_message_metadata pv_message_metadata_1 = {0};
	char ip_str[20] = {0};
	int readSize = 0;
	int nbytes = 0;
	short total_pv_payload_len = 0;
	void *packet_offset = NULL;
	int pv_sock = THREAD_FD(thread);
	pv_peer_accept_info *pv_peer_accept_info = THREAD_ARG(thread);
	short short_2_data = 0;
	char char_1_data = 0;
	int int_4_data = 0;

	pv_event(PV_ACCEPT_PEER_READ_MESSAGE, pv_sock, pv_peer_accept_info);

	readSize = PV_HEADER_SIZE;
	nbytes = stream_read_try (pv_peer_accept_info->packet_data_in, pv_peer_accept_info->fd, readSize);
	if(nbytes != PV_HEADER_SIZE)
	{
		PRINT_MESSAGE("%s : %d : PV Header read bytes error nbytes read %d PV_HEADER_SIZE %d\n", __func__, __LINE__, nbytes, PV_HEADER_SIZE);			
		return PV_FAIL;
	}

	packet_offset = pv_peer_accept_info->packet_data_in->data;

	total_pv_payload_len = stream_getw(pv_peer_accept_info->packet_data_in);

	PRINT_MESSAGE("%s : %d : ----------------------------------- \n", __func__, __LINE__);
	PRINT_MESSAGE("%s : %d : PKT--- Total Len: %d -- \n", __func__, __LINE__, total_pv_payload_len);


	char_1_data = stream_getc(pv_peer_accept_info->packet_data_in);
	if(char_1_data != 2)
	{
		PRINT_MESSAGE("%s : %d : PV message received from the neighbour is not of Type 2(UPDATE)\n", __func__, __LINE__);
		return PV_FAIL;
	}

	PRINT_MESSAGE("%s : %d : ----------------------------------- \n", __func__, __LINE__);
	PRINT_MESSAGE("%s : %d : PKT--- Type: %d -- \n", __func__, __LINE__, char_1_data);

	readSize = total_pv_payload_len - PV_HEADER_SIZE; 
	nbytes = stream_read_try (pv_peer_accept_info->packet_data_in, pv_peer_accept_info->fd, readSize);
	if(nbytes != readSize)
	{
		PRINT_MESSAGE("%s : %d : PV Pure Payload read bytes error\n", __func__, __LINE__);
		return PV_FAIL;
	}

	packet_offset = packet_offset + PV_PAYLOAD_START_OFFSET;

	memcpy(&(pv_message_metadata_1.su_received), &(pv_peer_accept_info->su), sizeof(union sockunion));


	if( pv_parse_pure_payload(&pv_message_metadata_1, packet_offset, total_pv_payload_len - PV_HEADER_SIZE, total_pv_payload_len, pv_peer_accept_info ) != PV_SUCCESS)
	{
		PRINT_MESSAGE("%s : %d : Error in pv_parse_pure_payload \n", __func__, __LINE__);
		pv_cleanup_pv_metadata(&pv_message_metadata_1);
		return PV_FAIL;
	}

	if(pv_add_route_to_rt_row(&pv_message_metadata_1, TYPE_OTHER) ==  PV_FAIL)
	{
		PRINT_MESSAGE("%s : %d : Error in pv_add_route_to_rt_row \n", __func__, __LINE__);
		pv_cleanup_pv_metadata(&pv_message_metadata_1);
		return PV_FAIL;
	}	


	send_advt_to_neighbours(&pv_message_metadata_1, TYPE_OTHER);
	
	stream_put(pv_peer_accept_info->packet_data_in, NULL, 0);
	stream_reset(pv_peer_accept_info->packet_data_in);


	/*** cleanup pv_message_metadata_1 ***/
	pv_cleanup_pv_metadata(&pv_message_metadata_1);


	return PV_SUCCESS;
}

int pv_cleanup_pv_metadata(pv_message_metadata *pv_message_metadata_1)
{


	struct listnode *nodek, *nnode, *nodek1, *nnode1;
	struct prefix_ipv4 *p = NULL;
	ases_path_number *ases_ptr = NULL;

	for (ALL_LIST_ELEMENTS (pv_message_metadata_1->ases_no, nodek1, nnode1, ases_ptr))
	{
		free(ases_ptr);
	}
	list_delete_all_node(pv_message_metadata_1->ases_no);
	list_free(pv_message_metadata_1->ases_no);

	for (ALL_LIST_ELEMENTS (pv_message_metadata_1->prefix_ipv4, nodek, nnode, p))
	{	
		free(p);
	}
	list_delete_all_node(pv_message_metadata_1->prefix_ipv4);
	list_free(pv_message_metadata_1->prefix_ipv4);



	return PV_SUCCESS;	
}

int pv_parse_pure_payload(pv_message_metadata *pv_message_metadata_1, void *start_pure_payload_offset, int total_pure_pay_len, int total_pv_payload_len, pv_peer_accept_info *pv_peer_accept_info)
{


	uint16_t path_attr_len = 0;
	int i = 0;
	uint8_t  nlri_tuples = 0;
	struct prefix_ipv4 *prefix_ptr = NULL;
	uint16_t nlri_attr_len = 0;
	ases_path_number *ases_path_number_1 = NULL;
	int no_ases = 0;
	struct in_addr in;

	unsigned int prefix = 0;
	short short_2_data = 0;
	char char_1_data = 0;
	int int_4_data = 0;
	union sockunion manil = {0};

	path_attr_len = stream_getw(pv_peer_accept_info->packet_data_in);
	PRINT_MESSAGE("%s : %d : ----------------------------------- \n", __func__, __LINE__);
	PRINT_MESSAGE("%s : %d : PKT--- Attr Len: %d -- \n", __func__, __LINE__, path_attr_len);


	nlri_attr_len = total_pv_payload_len - PV_HEADER_SIZE - 2 - path_attr_len;
	nlri_tuples = nlri_attr_len / 5 ;
	pv_message_metadata_1->nlri_tuples = nlri_tuples;
	PRINT_MESSAGE("%s : %d : PKT--- NLRI Tuples Count: %d -- \n", __func__, __LINE__, nlri_tuples);

	start_pure_payload_offset += 2; 

	/* COST */

	start_pure_payload_offset += 4; 

	short_2_data = stream_getw(pv_peer_accept_info->packet_data_in);
	short_2_data = stream_getw(pv_peer_accept_info->packet_data_in);

	pv_message_metadata_1->cost = stream_getl(pv_peer_accept_info->packet_data_in);
	PRINT_MESSAGE("%s : %d : ----------------------------------- \n", __func__, __LINE__);
	PRINT_MESSAGE("%s : %d : PKT--- COST VAL: %d -- \n", __func__, __LINE__, pv_message_metadata_1->cost );
	start_pure_payload_offset += 4; 

	/* ASES */
	short_2_data = stream_getw(pv_peer_accept_info->packet_data_in);
	start_pure_payload_offset += 2; 
	short_2_data = stream_getw(pv_peer_accept_info->packet_data_in);
	PRINT_MESSAGE("%s : %d : ----------------------------------- \n", __func__, __LINE__);
	PRINT_MESSAGE("%s : %d : PKT--- ASES ATTR'S LEN: %d -- \n", __func__, __LINE__, short_2_data);
	start_pure_payload_offset += 2; 

	no_ases = stream_getw(pv_peer_accept_info->packet_data_in);
	PRINT_MESSAGE("%s : %d : ----------------------------------- \n", __func__, __LINE__);
	PRINT_MESSAGE("%s : %d : PKT--- ASES NO'S: %d -- \n", __func__, __LINE__, no_ases );
	pv_message_metadata_1->no_of_ases = no_ases;
	start_pure_payload_offset += 2; 

	pv_message_metadata_1->prefix_ipv4 = list_new();
	pv_message_metadata_1->ases_no = list_new();

	for(i=1; i<=no_ases; ++i )
	{
		ases_path_number_1 = malloc(sizeof(ases_path_number));
		if(!ases_path_number_1)
		{
			PRINT_MESSAGE("%s : %d : Memory allocation failed\n", __func__, __LINE__);
			return PV_FAIL;
		}	
		memset(ases_path_number_1, 0 , sizeof(ases_path_number));
		ases_path_number_1->ases_number = stream_getl(pv_peer_accept_info->packet_data_in);
		listnode_add(pv_message_metadata_1->ases_no, ases_path_number_1);

		PRINT_MESSAGE("%s : %d : PKT------- ASES NO : %d -- \n", __func__, __LINE__, ases_path_number_1->ases_number);
		ases_path_number_1 = NULL;
		start_pure_payload_offset += 4; 
	}

	/* Next hop */
	start_pure_payload_offset += 4; 
	short_2_data = stream_getw(pv_peer_accept_info->packet_data_in);
	short_2_data = stream_getw(pv_peer_accept_info->packet_data_in);

	
	pv_message_metadata_1->nexthop = stream_getl(pv_peer_accept_info->packet_data_in);
	in.s_addr = pv_message_metadata_1->nexthop;
	
	PRINT_MESSAGE("%s : %d : ----------------------------------- \n", __func__, __LINE__);
	PRINT_MESSAGE("%s : %d : PKT--- NEXT HOP : %s -- \n", __func__, __LINE__, inet_ntoa(in));

	start_pure_payload_offset += 4; 

	/***manil.sin.sin_addr.s_addr = pv_message_metadata_1->nexthop;
	  memcpy(&(pv_message_metadata_1->su_received), &manil, sizeof(union sockunion));**/

	/* NLRI */
	PRINT_MESSAGE("%s : %d : ----------------------------------- \n", __func__, __LINE__);
	for(i=1; i<=nlri_tuples; ++i )
	{

		prefix_ptr = malloc(sizeof (struct prefix_ipv4));	
		if(!prefix_ptr)
		{
			PRINT_MESSAGE("%s : %d : Memory allocation failed\n", __func__, __LINE__);
			return PV_FAIL;
		}	
		memset(prefix_ptr, 0 , sizeof(struct prefix_ipv4));

		
		prefix_ptr->prefixlen = stream_getc(pv_peer_accept_info->packet_data_in);
		start_pure_payload_offset += 1; 

		
		prefix_ptr->prefix.s_addr = stream_getl(pv_peer_accept_info->packet_data_in);
		listnode_add(pv_message_metadata_1->prefix_ipv4, prefix_ptr);			
		
		memset(&in, 0 , sizeof(struct in_addr));
		
		in.s_addr = prefix_ptr->prefix.s_addr;
		PRINT_MESSAGE("%s : %d : PKT--- NLRI LEN : %d -- \n", __func__, __LINE__, prefix_ptr->prefixlen);
		PRINT_MESSAGE("%s : %d : PKT--- NLRI PREFIX : %s -- \n", __func__, __LINE__, inet_ntoa(in));

		start_pure_payload_offset += 4; 

		prefix_ptr = NULL;
	}
	PRINT_MESSAGE("%s : %d : ----------------------------------- \n", __func__, __LINE__);
	return PV_SUCCESS;
}

//check route in route_table_column. Single input p.
int pv_check_route_in_rt_column(struct prefix_ipv4 *p, struct route_node **out)
{


	struct route_node *node;
	struct in_addr in = {0};
	struct prefix_ipv4 pl = {0};

	memcpy(&pl, p, sizeof(struct prefix_ipv4));
	memcpy(&in, &pl.prefix, sizeof(struct in_addr));

	//apply_mask_ipv4 (&pl);
	node = route_node_lookup (pv_srvconf_params_1->pv_route_table_link->route_table_column, (struct prefix *) &pl);
	if (node)
	{
		*out = node;
		route_unlock_node (node);
		PRINT_MESSAGE("%s : %d : There is route in route table with the prefix %s. \n", __func__, __LINE__, inet_ntoa(in));
		return PV_ROUTE_ALREADY_EXISTS; 
	}

	PRINT_MESSAGE("%s : %d : There is no route in route table with the prefix %s . \n", __func__, __LINE__, inet_ntoa(in));


	return PV_ROUTE_NOT_FOUND; 
}   

//Add route in route_table_column. Single input p.
int pv_add_route_column(struct prefix_ipv4 *p, struct route_node **out)
{



	struct route_node *node;
	struct in_addr in = {0};
	struct prefix_ipv4 pl = {0};

	memcpy(&pl, p, sizeof(struct prefix_ipv4));

	if(pv_srvconf_params_1->pv_route_table_link->size > PV_ROUTE_TABLE_MAX_SIZE)
	{
		PRINT_MESSAGE("%s : %d : Cannot Add route as route do not exist\n", __func__, __LINE__);
		return PV_MAX_ROUTETABLE_SIZE_EXCEEDED;
	}

	memcpy(&in, &pl.prefix, sizeof(struct in_addr));

	//apply_mask_ipv4 (&pl);
	node = route_node_get (pv_srvconf_params_1->pv_route_table_link->route_table_column, (struct prefix*)&pl);
	node->info = (char *)"PATH_VECTOR_LEARNED_ROUTE"; /*** check **/
	*out = node;
	++(pv_srvconf_params_1->pv_route_table_link->size);



	return PV_SUCCESS; 
}


int pv_delete_route_column(struct prefix_ipv4 *p)
{


	struct route_node *node = NULL;
	pv_routing_table_row *pv_routing_table_row_1;
	struct listnode *nodek1, *nnode1;
	ases_path_number *ases_ptr = NULL;
	struct prefix_ipv4 pl = {0};
	struct prefix_ipv4  p2 = {0};
	struct route_node *rn = NULL;
	struct in_addr ip = {0};

	memcpy(&pl, p, sizeof(struct prefix_ipv4));

	for (ALL_LIST_ELEMENTS (pv_srvconf_params_1->pv_route_table_link->routing_table_row, nodek1, nnode1, pv_routing_table_row_1))
	{
		rn = pv_routing_table_row_1->route_node_row;
		p2.prefixlen = rn->p.prefixlen;
		p2.prefix = rn->p.u.prefix4;

		if(prefix_cmp((struct prefix *)&pl, (struct prefix *)&p2) == 0)
		{  

			pv_routing_table_row_1->route_node_row = NULL;
			for (ALL_LIST_ELEMENTS (pv_routing_table_row_1->ases_path_number_list, nodek1, nnode1, ases_ptr))
			{	
				free(ases_ptr);
			}	
			list_delete_all_node(pv_routing_table_row_1->ases_path_number_list);
			list_free(pv_routing_table_row_1->ases_path_number_list);
			listnode_delete(pv_srvconf_params_1->pv_route_table_link->routing_table_row, pv_routing_table_row_1);
			//route_node_delete (rn);
			route_unlock_node (rn);

		}	
	}

	/*
	   if( pv_check_route_in_rt_column(&pl, &node) == PV_ROUTE_ALREADY_EXISTS)
	   {
	   pv_routing_table_row_1 = node->info;
	   pv_routing_table_row_1->route_node_row = NULL;
	   for (ALL_LIST_ELEMENTS (pv_routing_table_row_1->ases_path_number_list, nodek1, nnode1, ases_ptr))
	   {	
	   free(ases_ptr);
	   }	
	   list_delete_all_node(pv_routing_table_row_1->ases_path_number_list);
	   list_free(pv_routing_table_row_1->ases_path_number_list);
	   listnode_delete(pv_srvconf_params_1->pv_route_table_link->routing_table_row, pv_routing_table_row_1);
	//route_node_delete (node);
	route_unlock_node (node);
	}
	else
	{
	PRINT_MESSAGE("%s : %d : Cannot delete route as route do not exist\n", __func__, __LINE__);
	return PV_FAIL;
	}*/
	return PV_SUCCESS;
}	

/* cost out param */
int pv_get_route_cost_in_rt_row(struct prefix_ipv4 *p, int *cost)
{


	struct route_node *node;
	struct in_addr in = {0};
	pv_routing_table_row *pv_routing_table_row_1 ;
	struct prefix_ipv4 pl = {0};
	struct listnode *nodek1, *nnode1;
	struct prefix_ipv4  p2 = {0};
	struct route_node *rn = NULL;
	struct in_addr ip = {0};

	memcpy(&pl, p, sizeof(struct prefix_ipv4));

	memcpy(&in, &pl.prefix, sizeof(struct in_addr));

	for (ALL_LIST_ELEMENTS (pv_srvconf_params_1->pv_route_table_link->routing_table_row, nodek1, nnode1, pv_routing_table_row_1))
	{
		rn = pv_routing_table_row_1->route_node_row;
		p2.prefixlen = rn->p.prefixlen;
		p2.prefix = rn->p.u.prefix4;

		if(prefix_cmp((struct prefix *)&pl, (struct prefix *)&p2) == 0)
		{  
			*cost = pv_routing_table_row_1->cost;


			break;
		}	
	}

	/**apply_mask_ipv4 (&pl);
	  node = route_node_lookup (pv_srvconf_params_1->pv_route_table_link->route_table_column, ( struct prefix *)&pl);
	  if (node == NULL)
	  {
	  PRINT_MESSAGE("%s : %d : There is no route in route table with the prefix %s\n", __func__, __LINE__, inet_ntoa(in));
	  route_unlock_node (node);
	  return PV_ROUTE_NOT_FOUND;
	  }

	  pv_routing_table_row_1 = node->info;
	 *cost = pv_routing_table_row_1->cost ;**/

	//node->info = (char *)"PATH_VECTOR_LEARNED_ROUTE";


	return PV_SUCCESS; 
}


int pv_add_route_to_rt_row(pv_message_metadata *pv_message_metadata_1, int type)	
{


	int old_cost = 0;
	struct route_node *node = NULL;
	pv_routing_table_row *pv_routing_table_row_1 = NULL;
	struct listnode *nodek, *nnode, *nodek1, *nnode1;
	struct prefix_ipv4 *p = NULL;
	ases_path_number *ases_path_number = NULL, *ases_ptr = NULL;

	if(type == TYPE_OTHER && pv_check_loop(pv_message_metadata_1) == PV_FAIL) // ignore this advertisement
		return PV_SUCCESS;

	for (ALL_LIST_ELEMENTS (pv_message_metadata_1->prefix_ipv4, nodek, nnode, p))
	{
		if( pv_check_route_in_rt_column(p, &node) == PV_ROUTE_ALREADY_EXISTS)
		{


			pv_get_route_cost_in_rt_row(p, &old_cost);
			if(pv_message_metadata_1->cost + 1 < old_cost) //Default hop count == cost 
			{
				pv_delete_route_column(p);

				if (pv_add_route_column(p, &node) != PV_SUCCESS)
					return PV_FAIL;

				pv_routing_table_row_1 = malloc(sizeof (pv_routing_table_row));
				if(!pv_routing_table_row_1)
				{
					PRINT_MESSAGE("%s : %d : Memory allocation failed\n", __func__, __LINE__);
					return PV_FAIL;
				}
				memset(pv_routing_table_row_1, 0 , sizeof(pv_routing_table_row));

				pv_routing_table_row_1->route_node_row = 	node;
				pv_routing_table_row_1->nexthop_IP = pv_message_metadata_1->nexthop; 
				pv_routing_table_row_1->cost = pv_message_metadata_1->cost + 1;

				pv_routing_table_row_1->ases_path_number_list = list_new();

				ases_path_number = malloc(sizeof(ases_path_number));
				if(!ases_path_number)
				{
					PRINT_MESSAGE("%s : %d : Memory allocation failed\n", __func__, __LINE__);
					return PV_FAIL;
				}	
				memset(ases_path_number, 0 , sizeof(ases_path_number));
				ases_path_number->ases_number = pv_srvconf_1.pv_current_AS_number;
				listnode_add(pv_routing_table_row_1->ases_path_number_list, ases_path_number);
				ases_path_number = NULL;

				for (ALL_LIST_ELEMENTS (pv_message_metadata_1->ases_no, nodek1, nnode1, ases_ptr))
				{
					ases_path_number = malloc(sizeof(ases_path_number));
					if(!ases_path_number)
					{
						PRINT_MESSAGE("%s : %d : Memory allocation failed\n", __func__, __LINE__);
						return PV_FAIL;
					}	
					memset(ases_path_number, 0 , sizeof(ases_path_number));
					ases_path_number->ases_number = ases_ptr->ases_number;
					listnode_add(pv_routing_table_row_1->ases_path_number_list, ases_path_number);
					ases_path_number = NULL;
				}  
				listnode_add(pv_srvconf_params_1->pv_route_table_link->routing_table_row, pv_routing_table_row_1);
				node->info = pv_routing_table_row_1; 
			}

		}
		else // NEW_ROUTE
		{


			if (pv_add_route_column(p, &node) != PV_SUCCESS)
				return PV_FAIL;

			pv_routing_table_row_1 = malloc(sizeof (pv_routing_table_row));
			if(!pv_routing_table_row_1)
			{
				PRINT_MESSAGE("%s : %d : Memory allocation failed\n", __func__, __LINE__);
				return PV_FAIL;
			}
			memset(pv_routing_table_row_1, 0 , sizeof(pv_routing_table_row));

			pv_routing_table_row_1->route_node_row = 	node;
			pv_routing_table_row_1->nexthop_IP = pv_message_metadata_1->nexthop; 
			if(type == TYPE_OTHER)
				pv_routing_table_row_1->cost = pv_message_metadata_1->cost + 1;
			else
				pv_routing_table_row_1->cost = pv_message_metadata_1->cost;

			pv_routing_table_row_1->ases_path_number_list = list_new();


			ases_path_number = malloc(sizeof(ases_path_number));
			if(!ases_path_number)
			{
				PRINT_MESSAGE("%s : %d : Memory allocation failed\n", __func__, __LINE__);
				return PV_FAIL;
			}	
			memset(ases_path_number, 0 , sizeof(ases_path_number));
			ases_path_number->ases_number = pv_srvconf_1.pv_current_AS_number;
			listnode_add(pv_routing_table_row_1->ases_path_number_list, ases_path_number);
			ases_path_number = NULL;

			if(type == TYPE_OTHER)
			{
				for (ALL_LIST_ELEMENTS (pv_message_metadata_1->ases_no, nodek1, nnode1, ases_ptr))
				{
					ases_path_number = malloc(sizeof(ases_path_number));
					if(!ases_path_number)
					{
						PRINT_MESSAGE("%s : %d : Memory allocation failed\n", __func__, __LINE__);
						return PV_FAIL;
					}	
					memset(ases_path_number, 0 , sizeof(ases_path_number));
					ases_path_number->ases_number = ases_ptr->ases_number;
					listnode_add(pv_routing_table_row_1->ases_path_number_list, ases_path_number);
					ases_path_number = NULL;
				}
			}

			listnode_add(pv_srvconf_params_1->pv_route_table_link->routing_table_row, pv_routing_table_row_1);
			node->info = pv_routing_table_row_1; 



		}

	}	



	return PV_SUCCESS;
}	

int pv_check_loop(pv_message_metadata *pv_message_metadata_1)	
{


	struct listnode *nodek, *nnode, *nodek1, *nnode1;
	ases_path_number *ases_ptr = NULL;

	for (ALL_LIST_ELEMENTS (pv_message_metadata_1->ases_no, nodek1, nnode1, ases_ptr))
	{
		if(ases_ptr->ases_number ==  pv_srvconf_1.pv_current_AS_number) // loop
		{
			PRINT_MESSAGE("%s : %d : My AS_PATH appeared from the neighbour advt. Loop Detected\n", __func__, __LINE__);
			return PV_FAIL;
		}
	}


	return PV_SUCCESS;
}	

int pv_open_connection_to_neighbours (struct thread *thread)
{

	struct sockaddr_in  addr = {0};
	int conn_Id = -1;
	pv_peer_connect_info *pv_peer_connect_info = NULL;
	int neigh_no = -1;

	pv_peer_connect_info = THREAD_ARG(thread);
	neigh_no = pv_peer_connect_info->neigh_no;



	switch(neigh_no)
	{
		case 1:
			addr.sin_family = AF_INET;
			addr.sin_port = htons(pv_srvconf_1.pv_first_neighbour_Port);
			addr.sin_addr.s_addr = pv_srvconf_1.pv_first_neighbour_ipAddress;
			break;
		case 2:
			addr.sin_family = AF_INET;
			addr.sin_port = htons(pv_srvconf_1.pv_second_neighbourPort);
			addr.sin_addr.s_addr = pv_srvconf_1.pv_second_neighbour_ipAddress;
			break;
		default:
			PRINT_MESSAGE("%s : %d : Invalid neighbour number\n", __func__, __LINE__);
			return PV_FAIL;
	}

	if( pv_open_connection(addr, &conn_Id) != PV_SUCCESS)
	{	


		pv_event(PV_CLIENT_CONNECT_TIMER, -1, pv_peer_connect_info);
		return PV_SUCCESS;
	}	

	pv_peer_connect_info->fd = conn_Id;
	pv_peer_connect_info->pv_neighbour_active_status = 1;
	memcpy(&(pv_peer_connect_info->su.sin) , &addr, sizeof(struct sockaddr_in));
	listnode_add (pv_srvconf_params_1->connect_peer_sockets, pv_peer_connect_info);

	return PV_SUCCESS;
}	


int pv_open_connection(struct sockaddr_in  addr, int *conn_Id)
{	


	int sock = -1, status = 0, tries = 0, flags = 0;
	struct timeval  timeout;
	int optVal;
	socklen_t optLen;

	timeout.tv_sec = 2;
	timeout.tv_usec = 0;

	fd_set writefds, exceptfds;

	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0)
	{
		close(sock);
		PRINT_MESSAGE("%s : %d : Client Socket creation error\n", __func__, __LINE__);
		return PV_SOCKET_CREATION_ERROR;
	}

	FD_ZERO(&writefds);
	FD_SET(sock, &writefds);
	FD_ZERO(&exceptfds);
	FD_SET(sock, &exceptfds);

	flags = fcntl(sock, F_GETFL, 0);
	fcntl(sock, F_SETFL, flags | O_NONBLOCK);

again:

	if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
	{  
		if (errno == EINPROGRESS)
			goto select_loop;  
		else if ((errno == EAGAIN || errno == EWOULDBLOCK ) && (++tries < 5) )
			goto again;
		else if (errno == EINTR)
			goto again;    
		else
		{
			close(sock);
			return     PV_SOCKET_CREATION_ERROR;
		}    

select_loop:         
		status = select(sock + 1, (fd_set *) NULL, &writefds, &exceptfds, &timeout);
		if (status == 0)
		{
			close(sock);
			return PV_SOCKET_READ_TIMEOUT_ERROR;
		}          
		if (status < 0)
		{
			if (errno == EINTR)
				goto select_loop;
			close(sock);    
			return PV_SOCKET_READ_ERROR;
		}

		if (FD_ISSET(sock, &exceptfds))
		{
			close(sock);
			return PV_SOCKET_READ_ERROR;
		}    

		if (!FD_ISSET(sock, &writefds))
			goto select_loop;

		optLen = sizeof(optVal);
		if(getsockopt(sock, SOL_SOCKET, SO_ERROR, &optVal, &optLen) < 0)
		{
			close(sock);
			return PV_SOCKET_CREATION_ERROR;
		}

		if(optVal != 0)
		{
			close(sock);
			return PV_SOCKET_CREATION_ERROR;
		}

	}
	*conn_Id = sock;


	return PV_SUCCESS;
}

int send_advt_to_neighbours(pv_message_metadata *pv_message_metadata_1, int type)
{



	struct listnode *nodek, *nnode;
	pv_peer_connect_info *pv_peer_connect_info_1 = NULL;
	char buf[20] = {0};

	for (ALL_LIST_ELEMENTS (pv_srvconf_params_1->connect_peer_sockets, nodek, nnode, pv_peer_connect_info_1))
	{
		/*** **/
		union sockunion one = pv_message_metadata_1->su_received;
		union sockunion two = pv_peer_connect_info_1->su;
		struct in_addr a = one.sin.sin_addr;
		struct in_addr b = two.sin.sin_addr;
		char aa[50] = {0};
		char bb[50] = {0};
		strcpy(aa, inet_ntoa(a));
		strcpy(bb, inet_ntoa(b));



		/*** **/
		if(pv_peer_connect_info_1->pv_neighbour_active_status == 1 && (strcmp(aa, bb) != 0))
		{
			/* send out */


			if( pkt_out_on_wire(pv_message_metadata_1, pv_peer_connect_info_1->fd, type) != PV_SUCCESS )
			{ 
				PRINT_MESSAGE("%s : %d : Cannot send data to peer %s \n", __func__, __LINE__, sockunion2str(&pv_peer_connect_info_1->su, buf, 20));
				return PV_FAIL;
			}	
		}	  
	}


	return PV_SUCCESS;	
}

int pkt_out_on_wire(pv_message_metadata *pv_message_metadata_1, int fd, int type)
{

	struct listnode *nodek, *nnode;
	ases_path_number *ases_ptr = NULL;
	int total_len_payload = 0, total_attr_len = 0, ases_tlv_len = 0, bytes = 0;
	struct prefix_ipv4 *p = NULL;

	struct stream *s = stream_new (PV_MAX_PACKET_SIZE);

	total_attr_len = PV_COST_LEN_TLV_SIZE + 
		(PV_ASPATH_TYPE_FEILD_SIZE + PV_ASPATH_LEN_FEILD_SIZE + PV_NOASES_LEN_FEILD_SIZE +
		 (pv_message_metadata_1->no_of_ases + 1) * PV_ASESNO_EACH_FEILD_SIZE) +
		PV_NHOP_LEN_TLV_SIZE;

	total_len_payload = PV_HEADER_SIZE + PV_ATTR_LEN_FEILD_SIZE + total_attr_len + (pv_message_metadata_1->nlri_tuples) * PV_NLRITUPLE_FEILD_SIZE;

	ases_tlv_len = (pv_message_metadata_1->no_of_ases + 1) * PV_ASESNO_EACH_FEILD_SIZE + PV_NOASES_LEN_FEILD_SIZE;

	stream_putw (s, total_len_payload);

	stream_putc (s, 2);


	stream_putw (s, total_attr_len);

	/* cost */
	stream_putw (s, 0); 
	stream_putw (s, 4);
	if(type == TYPE_OTHER)
	{
		stream_putl (s, pv_message_metadata_1->cost + 1); /* Increment */


	}
	else
	{
		stream_putl (s, pv_message_metadata_1->cost); 


	}

	/* ases */
	stream_putw (s, 1); 
	stream_putw (s, ases_tlv_len);

	stream_putw (s, pv_message_metadata_1->no_of_ases + 1);

	stream_putl (s, pv_srvconf_1.pv_current_AS_number); /* self */


	if(type == TYPE_OTHER)
	{   

		for (ALL_LIST_ELEMENTS (pv_message_metadata_1->ases_no, nodek, nnode, ases_ptr))
		{	
			stream_putl (s, ases_ptr->ases_number); 
		}

	}
	/* Next hop */
	stream_putw (s, 2); 
	stream_putw (s, 4);
	stream_putl (s, pv_srvconf_1.pv_current_ipAddress); /* Its me */


	/*NLRI */

	for (ALL_LIST_ELEMENTS (pv_message_metadata_1->prefix_ipv4, nodek, nnode, p))
	{
		stream_putc (s, p->prefixlen);
		stream_putl (s, p->prefix.s_addr);

	}	  


	/* flush data */
	bytes = stream_flush(s, fd);

	if(bytes != total_len_payload)
	{
		PRINT_MESSAGE("%s : %d : Error in flushing data\n", __func__, __LINE__);
		return PV_FAIL;
	}


	return PV_SUCCESS;
}

int pv_build_self_metadata()
{


	struct in_addr in= {0};
	union sockunion *su = NULL;
	ases_path_number *ases_path_number_1 = NULL;
	struct prefix_ipv4 *prefix_ptr = NULL;

	in.s_addr = pv_srvconf_1.pv_current_ipAddress;
	su = sockunion_str2su(inet_ntoa(in)); /*** Memory hidden. Clean it **/

	memcpy(&(pv_message_metadata_self.su_received), su, sizeof(union sockunion));
	pv_message_metadata_self.nlri_tuples = 1;
	pv_message_metadata_self.cost = 0; 
	pv_message_metadata_self.nexthop = pv_srvconf_1.pv_current_ipAddress;

	pv_message_metadata_self.no_of_ases = 0;
	pv_message_metadata_self.prefix_ipv4 = list_new();
	pv_message_metadata_self.ases_no = list_new();
	ases_path_number_1 = malloc(sizeof(ases_path_number));
	if(!ases_path_number_1)
	{
		PRINT_MESSAGE("%s : %d : Memory allocation failed\n", __func__, __LINE__);
		return PV_FAIL;
	}	
	memset(ases_path_number_1, 0 , sizeof(ases_path_number));

	ases_path_number_1->ases_number = pv_srvconf_1.pv_current_AS_number;
	listnode_add(pv_message_metadata_self.ases_no, ases_path_number_1);

	prefix_ptr = malloc(sizeof (struct prefix_ipv4));	
	if(!prefix_ptr)
	{
		PRINT_MESSAGE("%s : %d : Memory allocation failed\n", __func__, __LINE__);
		return PV_FAIL;
	}	
	memset(prefix_ptr, 0 , sizeof(struct prefix_ipv4));

	prefix_ptr->prefixlen = 24;
	prefix_ptr->prefix.s_addr = pv_srvconf_1.pv_current_ipAddress;
	listnode_add(pv_message_metadata_self.prefix_ipv4, prefix_ptr);	



	return PV_SUCCESS;
	/***To cleanup **/
}

int pv_adv_self_prefix()
{


	if(pv_add_route_to_rt_row(&pv_message_metadata_self, TYPE_SELF) ==  PV_FAIL)
	{
		PRINT_MESSAGE("%s : %d : Error in pv_add_route_to_rt_row \n", __func__, __LINE__);
		return PV_FAIL;
	}
	send_advt_to_neighbours(&pv_message_metadata_self, TYPE_SELF);
	return PV_SUCCESS;

}

int pv_print_route_table_to_file(struct thread *thread)
{
	printf("%s : %d : entry 1111111111111111111111111111111\n", __func__, __LINE__ );
	fflush(stdout);
	FILE *stream = NULL;
	char str[RTE_MAX_SIZE] = {0};
	char str_ases[400] = {0};
	struct route_table *table = NULL;
	struct route_node *rn = NULL;
	pv_routing_table_row *pv_routing_table_row = NULL;
	int prefi_len = 0;
	struct in_addr ip = {0};
	struct in_addr mask = {0};
	struct in_addr nhop = {0};
	char ip_str[20] = {0};
	char mask_str[20] = {0};
	char nhop_str[20] = {0};
	struct listnode *nodek1, *nnode1;
	ases_path_number *ases_ptr = NULL;
	void *p = str_ases;
	int cost = 0;
	int i = 0;
	
	pv_event(PV_PRINT_RT_TABLE_TIMER, -1, NULL); // calls pv_accept on read
	
    open_rte_file(&stream);
	
	sprintf(str, "\nIP-----MASK-----NEXTHOP-----COST-----AS_PATH\n");
	if(fputs (str, stream) == EOF)
		{
			PRINT_MESSAGE("%s : %d : Unable to write data to RTE file\n", __func__, __LINE__);
			return PV_FAIL;
		}
		fflush(stream);
	memset(str, 0 , RTE_MAX_SIZE);
	
	for (ALL_LIST_ELEMENTS (pv_srvconf_params_1->pv_route_table_link->routing_table_row, nodek1, nnode1, pv_routing_table_row))
	{
		printf("%s : %d :  6666666666666666  \n", __func__, __LINE__ );
		fflush(stdout);
		rn = pv_routing_table_row->route_node_row;
		prefi_len = rn->p.prefixlen;
		ip = rn->p.u.prefix4;
		strcpy(ip_str, inet_ntoa(ip));
		masklen2ip(prefi_len, &mask);
		strcpy(mask_str, inet_ntoa(mask));
		nhop.s_addr = pv_routing_table_row->nexthop_IP;
		strcpy(nhop_str, inet_ntoa(nhop));
		cost = pv_routing_table_row->cost;
		
		for (ALL_LIST_ELEMENTS (pv_routing_table_row->ases_path_number_list, nodek1, nnode1, ases_ptr))
		{
			sprintf(str_ases + i, "%d ,", ases_ptr->ases_number);
			i = i + 10;
		}	
		
		sprintf(str, "%s-----%s-----%s-----%d-----%s\n", ip_str, mask_str, nhop_str, cost, str_ases);
		
		if(fputs (str, stream) == EOF)
		{
			PRINT_MESSAGE("%s : %d : Unable to write data to RTE file\n", __func__, __LINE__);
			return PV_FAIL;
		}
		fflush(stream);
		
		memset(str_ases, 0 , 400);
		memset(mask_str, 0 , 20);
		memset(nhop_str, 0 , 20);
		memset(ip_str, 0 , 20);
		memset(&ip, 0 , sizeof(struct in_addr));
		cost = 0;
		memset(str, 0 , RTE_MAX_SIZE);
		i = 0;
	}
	close_rte_file(stream);
	printf("%s : %d : exit 22222222222222222222222222222\n", __func__, __LINE__ );
	fflush(stdout);
	return PV_SUCCESS;
}

#endif
