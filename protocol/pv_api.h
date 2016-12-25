#if defined(PATH_VECTOR_INCLUDED)
#ifndef _PV_API_H
#define _PV_API_H

#include <sys/utsname.h>

#define PV_RTABLE_FILENAME_AS1 "/tmp/pv_rtable_1.txt"
#define PV_RTABLE_FILENAME_AS2 "/tmp/pv_rtable_2.txt"
#define PV_RTABLE_FILENAME_AS3 "/tmp/pv_rtable_3.txt"
#define PV_RTABLE_FILENAME_AS4 "/tmp/pv_rtable_4.txt"
#define PV_RTABLE_FILENAME_AS5 "/tmp/pv_rtable_5.txt"


#define PRINT_MSG(S) pv_error_console(S)

#define PRINT_MESSAGE(format, args...) fprintf(stdout, format, args);\
	fflush(stdout)

extern void pv_update_sock_send_buffer_size (int);
extern void pv_error_console(const char *str);
extern int open_rte_file(FILE **);
extern int close_rte_file(FILE *);

#endif
#endif
