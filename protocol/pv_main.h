#if defined(PATH_VECTOR_INCLUDED)
#ifndef _PV_MAIN_H
#define _PV_MAIN_H

#include <stdint.h>
#include <errno.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h>
#include <ctype.h>
#include "sockunion.h"

#define PV_DAEMON_PID_FILE_AS1 "path_vector_1"
#define PV_DAEMON_PID_FILE_AS2 "path_vector_2"
#define PV_DAEMON_PID_FILE_AS3 "path_vector_3"
#define PV_DAEMON_PID_FILE_AS4 "path_vector_4"
#define PV_DAEMON_PID_FILE_AS5 "path_vector_5"

#define PV_SUCCESS 1
#define PV_FAIL 0
#define PV_ROUTE_NOT_FOUND -1
#define PV_ROUTE_ALREADY_EXISTS -2
#define PV_MAX_ROUTETABLE_SIZE_EXCEEDED -3
#define PV_SOCKET_CREATION_ERROR -4
#define PV_SOCKET_READ_TIMEOUT_ERROR -5
#define PV_SOCKET_READ_ERROR -6

#define PV_HEADER_SIZE 3
#define PV_ATTR_LEN_FEILD_SIZE 2
#define PV_COST_LEN_TLV_SIZE 8
#define PV_NHOP_LEN_TLV_SIZE 8
#define PV_ASPATH_TYPE_FEILD_SIZE 2
#define PV_ASPATH_LEN_FEILD_SIZE 2
#define PV_NOASES_LEN_FEILD_SIZE 2
#define PV_ASESNO_EACH_FEILD_SIZE 4
#define PV_NLRITUPLE_FEILD_SIZE 5
#define PV_HEADER_TOTAL_LEN_FEILD_OFFSET 0
#define PV_HEADER_TYPE_FEILD_OFFSET PV_HEADER_TOTAL_LEN_FEILD_OFFSET + 2
#define PV_PAYLOAD_START_OFFSET PV_HEADER_SIZE
#define PV_PATHLEN_ATTRIBUTE_FEILD_OFFSET PV_HEADER_SIZE + 0

#define PV_MAX_PACKET_SIZE 4096
#define TYPE_SELF 0
#define TYPE_OTHER 1
#define RTE_MAX_SIZE 4000


typedef struct  {
	uint16_t total_length ; /* the total length of the message, including the header in bytes*/
	uint8_t type; /* 2 - UPDATE */
}pv_message_header;

/* Type can be 
   COST (Type Code 0): 4 bytes fixed
   AS_PATH (Type Code 1): Variable bytes
LENGTH: number of ASes. 2 Bytes Fixed.
VALUE:  one or more AS Numbers. Each of 32 Bytes
NEXT_HOP (Type Code 2): 4 Bytes Fixed

 */
typedef struct  {
	uint16_t                            type;
	uint16_t                            length;         
	void                                *value;
}path_attributes;

/*typedef struct  {
  struct list *path_attributes_list ;
  }path_attributes_list;*/

typedef struct  {
	uint32_t  ases_number;
} ases_path_number;

typedef struct  {
	uint8_t  no_of_ases ; 
	struct list *ases_path_list;
} ases_path_attribute;

/* NLRI */
typedef struct 
{
	uint8_t nlri_length;
	uint32_t nlri_prefix;
}pv_nlri;

/*typedef struct 
  {
  struct list *nlri_list;
  }pv_nlri_list;*/

typedef struct  {
	pv_message_header pv_message_header;
	uint16_t path_attr_len ; /*total length of the Path Attributes field in bytes excluding attr len feild*/
	struct list *path_attributes_list;
	struct list *pv_nlri_list;
}pv_message;

typedef struct  {
	union sockunion su_received;
	uint8_t nlri_tuples;
	uint32_t cost;
	uint32_t nexthop;
	struct list *prefix_ipv4 ; /*NLRI */
	struct list *ases_no;
	uint16_t no_of_ases;	
}pv_message_metadata;

typedef struct pv_routing_table_link_s
{
	struct route_table *route_table_column; // containe prefix info. Struct route_node's
	uint32_t size;
	struct list *routing_table_row ; // list of pv_routing_table_row_s
}pv_routing_table_link;

typedef struct pv_routing_table_row_s
{
	struct route_node *route_node_row; // containe prefix_ipv4 info
	uint32_t nexthop_IP;
	uint32_t cost;
	struct list *ases_path_number_list;
}pv_routing_table_row;

#endif
#endif

