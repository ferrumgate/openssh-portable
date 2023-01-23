//#include "unit_ferrum_common.h"
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sys_domain.h>
#include <sys/kern_control.h>
#include <fcntl.h>
#include <net/if.h>
#include <net/if_utun.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <stdlib.h>

extern int32_t test_ferrum();

// Simple User-Tunneling Proof of Concept - extends listing 17-15 in book
// 
// Compiles for both iOS and OS X..
//
// Coded by Jonathan Levin. Go ahead; Copy, improve - all rights allowed.
//
//  (though credit where credit is due would be nice ;-)

/* Helper functions that tries to open utun device
 * return -2 on early initialization failures (utun not supported
 * at all (old OS X) and -1 on initlization failure of utun
 * device (utun works but utunX is already used */
static
int
utun_open_helper(struct ctl_info ctlInfo, int utunnum)
{
    struct sockaddr_ctl sc;
    int fd;

    fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);

    if (fd < 0)
    {
        fprintf(stderr,"Opening utun%d failed (socket(SYSPROTO_CONTROL))\n",
            utunnum);
        return -2;
    }

    if (ioctl(fd, CTLIOCGINFO, &ctlInfo) == -1)
    {
        close(fd);
        fprintf(stderr,"Opening utun%d failed (ioctl(CTLIOCGINFO))\n",
            utunnum);
        return -2;
    }


    sc.sc_id = ctlInfo.ctl_id;
    sc.sc_len = sizeof(sc);
    sc.sc_family = AF_SYSTEM;
    sc.ss_sysaddr = AF_SYS_CONTROL;
    sc.sc_unit = utunnum+1;


    /* If the connect is successful, a utun%d device will be created, where "%d"
     * is (sc.sc_unit - 1) */

    if (connect(fd, (struct sockaddr *)&sc, sizeof(sc)) < 0)
    {
       fprintf(stderr,"Opening utun%d failed (connect(AF_SYS_CONTROL))\n",
            utunnum);
        close(fd);
        return -1;
    }
 if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0)
    {
        close(fd);
        return -1;
    }
   if (fcntl(fd, F_SETFD, FD_CLOEXEC) < 0)
    {
        close(fd);
        return -1;
    }

    return fd;
}

int
open_darwin_utun(const char *dev, const char *dev_type, const char *dev_node,int *tunnumber)
{
    struct ctl_info ctlInfo;
    int fd=-1;
    char utunname[20];
    int utunnum = -1;
    socklen_t utunname_len = sizeof(utunname);

    /* dev_node is simply utun, do the normal dynamic utun
     * otherwise try to parse the utun number */
    if (dev_node && (strcmp("utun", dev_node) != 0 ))
    {
        if (sscanf(dev_node, "utun%d", &utunnum) != 1)
        {
           fprintf(stderr,"Cannot parse 'dev-node %s' please use 'dev-node utunX'"
                "to use a utun device number X", dev_node);
        }
    }



    //CLEAR(ctlInfo);
    memset(&ctlInfo,0,sizeof(ctlInfo));
    if (strlcpy(ctlInfo.ctl_name, UTUN_CONTROL_NAME, sizeof(ctlInfo.ctl_name)) >=
        sizeof(ctlInfo.ctl_name))
    {
       fprintf(stderr,"Opening utun: UTUN_CONTROL_NAME too long");
       return -1;
    }

    /* try to open first available utun device if no specific utun is requested */
   
    if (utunnum == -1)
    {
        for (utunnum = 0; utunnum < 255; utunnum++)
        {
            char ifname[20];
            /* if the interface exists silently skip it */
            snprintf(ifname, sizeof(ifname), "utun%d", utunnum);
            if (if_nametoindex(ifname))
            {
                continue;
            }
            fd = utun_open_helper(ctlInfo, utunnum);
            /* Break if the fd is valid,
             * or if early initialization failed (-2) */
            if (fd !=-1)
            {
                break;
            }
        }
    }
    else
    {
        fd = utun_open_helper(ctlInfo, utunnum);
    }

    /* opening an utun device failed */
    

    if (fd < 0)
    {
        return -1;
    }

    /* Retrieve the assigned interface name. */
    if (getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, utunname, &utunname_len))
    {
        fprintf(stderr,"%s\n", "Error retrieving utun interface name");
        return -1;
    }


   fprintf(stderr,"opened darwin utun device %s\n", utunname);
   *tunnumber=utunnum;
    return fd;
}


int main(){
  /*   if(test_ferrum())
    exit(1); */
    int utunfd =  open_darwin_utun(NULL,NULL,"utun");

  if (utunfd == -1)
	{
		fprintf(stderr,"Unable to establish UTUN descriptor - aborting\n");
		exit(1);
	}

  fprintf(stderr,"Utun interface is up.. Configure IPv4 using \"ifconfig utun1 _ipA_ _ipB_\"\n");
  fprintf(stderr,"                       Configure IPv6 using \"ifconfig utun1 inet6 _ip6_\"\n");
  fprintf(stderr,"Then (e.g.) ping _ipB_ (IPv6 will automatically generate ND messages)\n");

    getchar();

  // PoC - Just dump the packets...
  for (;;)
	{
		unsigned char 	c[1500];
		int     len;
		int	i;

	
		len = read (utunfd,c, 1500);

		// First 4 bytes of read data are the AF: 2 for AF_INET, 1E for AF_INET6, etc..
		for (i = 4; i< len; i++)
		{
		   printf ("%02x ", c[i]);
		   if ( (i-4)%16 ==15) printf("\n");
		}
		printf ("\n");

		
	}

   return(0);
}