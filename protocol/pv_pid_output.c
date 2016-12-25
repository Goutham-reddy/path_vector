#if defined(PATH_VECTOR_INCLUDED)
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "pv_api.h"
#include "log.h"

#define PIDFILE_MASK 0644

/*****************************************************************************
 * Function Name      : pid_output                                           *
 *                                                                           *
 * Description        : This function gets pv process identifier  *
 *                                                                           *
 * Input(s)           : path  -  adds pid on the specified file name         *
 *                                                                           *
 * Output(s)          : None                                                 *
 *                                                                           *
 * Global Variables                                                          *
 * Referred           : None                                                 *
 *                                                                           *
 * Global Variables                                                          *
 * Modified           : None                                                 *
 *                                                                           *
 * Return Value(s)    : process identifier structure pointer                 *
 *                                                                           *
 *****************************************************************************/
pid_t	 pid_output(const char *path)
{
	int tmp;
	int fd;
	pid_t pid;
	char buf[16];
	struct flock lock;  
	mode_t oldumask;
	char buffer[1024];

	pid = getpid ();

	oldumask = umask(0777 & ~PIDFILE_MASK);
	fd = open (path, O_RDWR | O_CREAT, PIDFILE_MASK);
	if (fd < 0)
	{
		PRINT_MESSAGE("%s : %d : Can't create pid lock file %s (%s), exiting \n", __func__, __LINE__, path, safe_strerror(errno));
		umask(oldumask);
		exit(1);
	}
	else
	{
		size_t pidsize;

		umask(oldumask);
		memset (&lock, 0, sizeof(lock));

		lock.l_type = F_WRLCK;
		lock.l_whence = SEEK_SET;

		if (fcntl(fd, F_SETLK, &lock) < 0)
		{
			sprintf(buffer, "Could not lock pid_file %s, exiting", path);
			PRINT_MESSAGE("%s : %d : Could not lock pid_file %s, exiting \n", __func__, __LINE__, path);
			exit(1);
		}

		sprintf (buf, "%d\n", (int) pid);
		pidsize = strlen(buf);
		if ((tmp = write (fd, buf, pidsize)) != (int)pidsize)
		{
			PRINT_MESSAGE("%s : %d : Could not write pid %d to pid_file %s, rc was %d: %s \n", __func__, __LINE__, (int)pid,path,tmp, (char*)safe_strerror(errno));
		}
		else if (ftruncate(fd, pidsize) < 0)
		{
			PRINT_MESSAGE("%s : %d : Could not truncate pid_file %s to %u bytes: %s \n", __func__, __LINE__, path,(u_int)pidsize, (char*)safe_strerror(errno));
		} 
	}
	return pid;
}
#endif  //PATH_VECTOR_INCLUDED
