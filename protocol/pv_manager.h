#if defined(PATH_VECTOR_INCLUDED)
#ifndef _PV_MANAGER_H
#define _PV_MANAGER_H

#include "sockunion.h"
#include "pv_main.h"
#include "prefix.h"

#define PV_SOCKET_SNDBUF_SIZE 65536
#define PV_ROUTE_TABLE_MAX_SIZE 256

/* Mask assumed to be 24 */
/*#define AS1_IP  "127.0.0.2"
#define AS2_IP  "127.0.0.3"
#define AS3_IP  "127.0.0.4"
#define AS4_IP  "127.0.0.5"
#define AS5_IP  "127.0.0.6"*/

#define AS1_IP  "1.1.1.1"
#define AS2_IP  "2.2.2.2"
#define AS3_IP  "3.3.3.3"
#define AS4_IP  "4.4.4.4"
#define AS5_IP  "5.5.5.5"

#define AS1_PORT  55552
#define AS2_PORT  55553
#define AS3_PORT  55554
#define AS4_PORT  55555
#define AS5_PORT  55556

#define AS1_NUMBER 1
#define AS2_NUMBER 2
#define AS3_NUMBER 3
#define AS4_NUMBER 4
#define AS5_NUMBER 5

/*#define AS1_NEIGHBOUR_1_IP "127.0.0.3"
#define AS1_NEIGHBOUR_2_IP "127.0.0.6"
#define AS2_NEIGHBOUR_1_IP "127.0.0.2"
#define AS2_NEIGHBOUR_2_IP "127.0.0.4"
#define AS3_NEIGHBOUR_1_IP "127.0.0.3"
#define AS3_NEIGHBOUR_2_IP "127.0.0.5"
#define AS4_NEIGHBOUR_1_IP "127.0.0.6"
#define AS4_NEIGHBOUR_2_IP "127.0.0.4"
#define AS5_NEIGHBOUR_1_IP "127.0.0.2"
#define AS5_NEIGHBOUR_2_IP "127.0.0.5"*/

#define AS1_NEIGHBOUR_1_IP  "2.2.2.2"
#define AS1_NEIGHBOUR_2_IP  "5.5.5.5"
#define AS2_NEIGHBOUR_1_IP  "1.1.1.1"
#define AS2_NEIGHBOUR_2_IP  "3.3.3.3"
#define AS3_NEIGHBOUR_1_IP  "2.2.2.2"
#define AS3_NEIGHBOUR_2_IP  "4.4.4.4"
#define AS4_NEIGHBOUR_1_IP  "5.5.5.5"
#define AS4_NEIGHBOUR_2_IP  "3.3.3.3"
#define AS5_NEIGHBOUR_1_IP  "1.1.1.1"
#define AS5_NEIGHBOUR_2_IP  "4.4.4.4"

#define AS1_NEIGHBOUR_1_PORT 55553
#define AS1_NEIGHBOUR_2_PORT 55556
#define AS2_NEIGHBOUR_1_PORT 55552
#define AS2_NEIGHBOUR_2_PORT 55554
#define AS3_NEIGHBOUR_1_PORT 55553
#define AS3_NEIGHBOUR_2_PORT 55555
#define AS4_NEIGHBOUR_1_PORT 55554
#define AS4_NEIGHBOUR_2_PORT 55556
#define AS5_NEIGHBOUR_1_PORT 55555
#define AS5_NEIGHBOUR_2_PORT 55552

/* pv thread events */
enum pv_event
{
	PV_LISTENER_READ,
	PV_ACCEPT_PEER_READ_MESSAGE,
	PV_CLIENT_CONNECT_EVENT,
	PV_CLIENT_CONNECT_TIMER,
	PV_MY_UPDATE_TIMER,
	PV_NEIGHBOUR_UPDATE_TIMER,
	PV_PRINT_RT_TABLE_TIMER,
};

/* PV Peer Accept socket. 2 Lists are maintained*/
typedef struct pv_peer_accept_info_s
{
	int fd;
	union sockunion su;
	struct thread *thread;
	struct stream *packet_data_in;
}pv_peer_accept_info;

/* PV Peer Connect socket. 2 Lists are maintained*/
typedef struct pv_peer_connect_info_s
{
	int fd;
	union sockunion su;
	struct thread *thread;
	//stream *packet_data_in;
	char	pv_neighbour_active_status; /* 1 or 0*/
	int neigh_no;
}pv_peer_connect_info;


typedef struct pv_srvconf_params_s
{
	int	    listener_socket_id;
	struct	thread	*hPV_ListenerThread;
	/* Accepted sockets file fd's*/
	struct list *accepted_peer_sockets; // list of pv_peer_accept_info
	struct list *connect_peer_sockets; // list of pv_peer_connect_info
	struct  thread                 *hPVMyUpdate;
	//struct  thread                 *hPVNeighUpdate;
	struct  thread                 *hPV_rt_table_print;
	pv_routing_table_link *pv_route_table_link;
}pv_srvconf_params;


typedef struct pv_srvconf_s
{
	unsigned int        pv_current_ipAddress;
	unsigned int        pv_first_neighbour_ipAddress;
	unsigned int        pv_second_neighbour_ipAddress;
	unsigned short int  pv_currrent_Port;
	unsigned short int  pv_first_neighbour_Port;
	unsigned short int  pv_second_neighbourPort;
	unsigned short int                pv_current_AS_number;
	unsigned short int                pv_first_neighbour_AS_number;
	unsigned short int                pv_second_neighbour_AS_number;
} pv_srvconf;

extern int wr_pv_init(int);
extern int setup_connections_to_neighbour(unsigned char);
extern int pv_event(enum pv_event, int, void *);
extern int pv_listener ();
extern int pv_accept (struct thread *);
extern int pv_read_packet (struct thread *);
extern int pv_cleanup_pv_metadata(pv_message_metadata *);
extern int pv_parse_pure_payload(pv_message_metadata *, void *, int , int, pv_peer_accept_info *);
extern int pv_delete_route_column(struct prefix_ipv4 *);
extern int pv_get_route_cost_in_rt_row(struct prefix_ipv4 *, int *);
extern int pv_add_route_to_rt_row(pv_message_metadata *, int )	;
extern int pv_check_loop(pv_message_metadata *);
extern int pv_open_connection_to_neighbours (struct thread *);
extern int pv_open_connection(struct sockaddr_in , int *);
extern int send_advt_to_neighbours(pv_message_metadata *, int );
extern int pkt_out_on_wire(pv_message_metadata *, int , int );
extern int pv_build_self_metadata();
extern int pv_adv_self_prefix();
extern int pv_print_route_table_to_file(struct thread *);
extern int pv_check_route_in_rt_column(struct prefix_ipv4 *, struct route_node **);
extern int pv_add_route_column(struct prefix_ipv4 *p, struct route_node **out);
extern int pv_print_route_table_to_file_new();

#endif
#endif
