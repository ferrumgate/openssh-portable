/*
 * Copyright (c) 2005 Reyk Floeter <reyk@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "includes.h"

#include <sys/types.h>
#include <sys/ioctl.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "openbsd-compat/sys-queue.h"
#include "log.h"
#include "misc.h"
#include "sshbuf.h"
#include "channels.h"
#include "ssherr.h"


/*
 * This file contains various portability code for network support,
 * including tun/tap forwarding and routing domains.
 */

#if defined(SYS_RDOMAIN_LINUX) || defined(SSH_TUN_LINUX)
#include <linux/if.h>
#endif

#if defined(SYS_RDOMAIN_LINUX)
char *
sys_get_rdomain(int fd)
{
	char dev[IFNAMSIZ + 1];
	socklen_t len = sizeof(dev) - 1;

	if (getsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, dev, &len) == -1) {
		error("%s: cannot determine VRF for fd=%d : %s",
		    __func__, fd, strerror(errno));
		return NULL;
	}
	dev[len] = '\0';
	return strdup(dev);
}

int
sys_set_rdomain(int fd, const char *name)
{
	if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
	    name, strlen(name)) == -1) {
		error("%s: setsockopt(%d, SO_BINDTODEVICE, %s): %s",
		    __func__, fd, name, strerror(errno));
		return -1;
	}
	return 0;
}

int
sys_valid_rdomain(const char *name)
{
	int fd;

	/*
	 * This is a pretty crappy way to test. It would be better to
	 * check whether "name" represents a VRF device, but apparently
	 * that requires an rtnetlink transaction.
	 */
	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		return 0;
	if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
	    name, strlen(name)) == -1) {
		close(fd);
		return 0;
	}
	close(fd);
	return 1;
}
#elif defined(SYS_RDOMAIN_XXX)
/* XXX examples */
char *
sys_get_rdomain(int fd)
{
	return NULL;
}

int
sys_set_rdomain(int fd, const char *name)
{
	return -1;
}

int
valid_rdomain(const char *name)
{
	return 0;
}

void
sys_set_process_rdomain(const char *name)
{
	fatal("%s: not supported", __func__);
}
#endif /* defined(SYS_RDOMAIN_XXX) */

/*
 * This is the portable version of the SSH tunnel forwarding, it
 * uses some preprocessor definitions for various platform-specific
 * settings.
 *
 * SSH_TUN_LINUX	Use the (newer) Linux tun/tap device
 * SSH_TUN_FREEBSD	Use the FreeBSD tun/tap device
 * SSH_TUN_COMPAT_AF	Translate the OpenBSD address family
 * SSH_TUN_PREPEND_AF	Prepend/remove the address family
 */

/*
 * System-specific tunnel open function
 */
#ifdef FERRUM
#include <sys/random.h>
static int32_t srand_initted = 0;
static const char *charset =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
// fill with random characters
static void ferrum_util_fill_random(char *dest,size_t len){
     // init default ssed
    if (!srand_initted) {
        srand(time(NULL));
        srand_initted = 1;
    }
	char tmp[128];
	#ifndef SSH_TUN_DARWIN
    ssize_t ret=getrandom(tmp,sizeof(tmp),0);
	int randomError=ret==-1;
	if(randomError){
		fprintf(stderr,"/dev/urandom read error %s\n",strerror(errno));
	}
    #else
    int randomError=-1;
    #endif
	size_t setlen = strlen(charset);
	for (uint32_t i = 0; i < len&& i<sizeof(tmp); ++i) {
		size_t index =randomError ? (rand() % setlen):(tmp[i]%setlen);//if error occured
		dest[i] = charset[index];
	}
	
	
}

#endif

#if defined(SSH_TUN_LINUX)
#include <linux/if_tun.h>
#define TUN_CTRL_DEV "/dev/net/tun"

int
sys_tun_open(int tun, int mode, char **ifname)
{
	
	struct ifreq ifr;
	int fd = -1;
	const char *name = NULL;
	#ifdef FERRUM
	char random[9]={0};
	#endif

	if (ifname != NULL)
		*ifname = NULL;
	if ((fd = open(TUN_CTRL_DEV, O_RDWR)) == -1) {
		debug("%s: failed to open tunnel control device \"%s\": %s",
		    __func__, TUN_CTRL_DEV, strerror(errno));
		return (-1);
	}

	bzero(&ifr, sizeof(ifr));

	if (mode == SSH_TUNMODE_ETHERNET) {
		ifr.ifr_flags = IFF_TAP;
		name = "tap%d";
	} else {
		ifr.ifr_flags = IFF_TUN;
		name = "tun%d";
		#ifdef FERRUM
		ferrum_util_fill_random(random,8);
		snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "ferrum%s", random);
		#endif
	}
	ifr.ifr_flags |= IFF_NO_PI;

	if (tun != SSH_TUNID_ANY) {
		if (tun > SSH_TUNID_MAX) {
			debug("%s: invalid tunnel id %x: %s", __func__,
			    tun, strerror(errno));
			goto failed;
		}
		snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), name, tun);
	}

	if (ioctl(fd, TUNSETIFF, &ifr) == -1) {
		debug("%s: failed to configure tunnel (mode %d): %s", __func__,
		    mode, strerror(errno));
		goto failed;
	}

	if (tun == SSH_TUNID_ANY)
		debug("%s: tunnel mode %d fd %d", __func__, mode, fd);
	else
		debug("%s: %s mode %d fd %d", __func__, ifr.ifr_name, mode, fd);

	if (ifname != NULL && (*ifname = strdup(ifr.ifr_name)) == NULL)
		goto failed;

	return (fd);

 failed:
	close(fd);
	return (-1);
}
#endif /* SSH_TUN_LINUX */

/* SSH_TUN_DARWIN*/


#ifdef SSH_TUN_DARWIN
#include <sys/sys_domain.h>
#include <sys/kern_control.h>
#include <net/if_utun.h>
#include <net/if.h>
/* Darwin (MacOS X) is mostly "just use the generic stuff", but there
 * is always one caveat...:
 *
 * If IPv6 is configured, and the tun device is closed, the IPv6 address
 * configured to the tun interface changes to a lingering /128 route
 * pointing to lo0.  Need to unconfigure...  (observed on 10.5)
 */

/*
 * utun is the native Darwin tun driver present since at least 10.7
 * Thanks goes to Jonathan Levin for providing an example how to utun
 * (http://newosxbook.com/src.jl?tree=listings&file=17-15-utun.c)
 */



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
static
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

int
sys_tun_open(int tun, int mode, char **ifname)
{
	
	
	int fd = -1;
	const char *name = NULL;
	int tunnum=0;

	if (ifname != NULL)
		*ifname = NULL;
	if ((fd = open_darwin_utun(NULL,NULL,"utun", &tunnum)) == -1) {
		debug("failed to open tunnel device");
		return (-1);
	}

	*ifname=malloc(16);
	snprintf(*ifname,15,"utun%d",tunnum);
	
	return (fd);

 failed:
	close(fd);
	return (-1);
}


#endif

#ifdef SSH_TUN_FREEBSD
#include <sys/socket.h>
#include <net/if.h>

#ifdef HAVE_NET_IF_TUN_H
#include <net/if_tun.h>
#endif

int
sys_tun_open(int tun, int mode, char **ifname)
{
	
	struct ifreq ifr;
	char name[100];
	int fd = -1, sock;
	const char *tunbase = "tun";
#if defined(TUNSIFHEAD) && !defined(SSH_TUN_PREPEND_AF)
	int flag;
#endif

	if (ifname != NULL)
		*ifname = NULL;

	if (mode == SSH_TUNMODE_ETHERNET) {
#ifdef SSH_TUN_NO_L2
		debug("%s: no layer 2 tunnelling support", __func__);
		return (-1);
#else
		tunbase = "tap";
#endif
	}

	/* Open the tunnel device */
	if (tun <= SSH_TUNID_MAX) {
		snprintf(name, sizeof(name), "/dev/%s%d", tunbase, tun);
		fd = open(name, O_RDWR);
	} else if (tun == SSH_TUNID_ANY) {
		for (tun = 100; tun >= 0; tun--) {
			snprintf(name, sizeof(name), "/dev/%s%d",
			    tunbase, tun);
			if ((fd = open(name, O_RDWR)) >= 0)
				break;
		}
	} else {
		debug("%s: invalid tunnel %u\n", __func__, tun);
		return (-1);
	}

	if (fd < 0) {
		debug("%s: %s open failed: %s", __func__, name,
		    strerror(errno));
		return (-1);
	}

	/* Turn on tunnel headers */
#if defined(TUNSIFHEAD) && !defined(SSH_TUN_PREPEND_AF)
	flag = 1;
	if (mode != SSH_TUNMODE_ETHERNET &&
	    ioctl(fd, TUNSIFHEAD, &flag) == -1) {
		debug("%s: ioctl(%d, TUNSIFHEAD, 1): %s", __func__, fd,
		    strerror(errno));
		close(fd);
	}
#endif

	debug("%s: %s mode %d fd %d", __func__, name, mode, fd);

	/* Set the tunnel device operation mode */
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s%d", tunbase, tun);
	if ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		goto failed;

	if (ioctl(sock, SIOCGIFFLAGS, &ifr) == -1)
		goto failed;
	if ((ifr.ifr_flags & IFF_UP) == 0) {
		ifr.ifr_flags |= IFF_UP;
		if (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1)
			goto failed;
	}

	if (ifname != NULL && (*ifname = strdup(ifr.ifr_name)) == NULL)
		goto failed;

	close(sock);
	return (fd);

 failed:
	if (fd >= 0)
		close(fd);
	if (sock >= 0)
		close(sock);
	debug("%s: failed to set %s mode %d: %s", __func__, name,
	    mode, strerror(errno));
	return (-1);
}
#endif /* SSH_TUN_FREEBSD */

/*
 * System-specific channel filters
 */

#if defined(SSH_TUN_FILTER)
/*
 * The tunnel forwarding protocol prepends the address family of forwarded
 * IP packets using OpenBSD's numbers.
 */
#define OPENBSD_AF_INET		2
#define OPENBSD_AF_INET6	24

int
sys_tun_infilter(struct ssh *ssh, struct Channel *c, char *buf, int _len)
{
	int r;
	size_t len;
	char *ptr = buf;
#if defined(SSH_TUN_PREPEND_AF)
	char rbuf[CHAN_RBUF];
	struct ip iph;
#endif
#if defined(SSH_TUN_PREPEND_AF) || defined(SSH_TUN_COMPAT_AF)
	u_int32_t af;
#endif

	/* XXX update channel input filter API to use unsigned length */
	if (_len < 0)
		return -1;
	len = _len;

#if defined(SSH_TUN_PREPEND_AF)
	if (len <= sizeof(iph) || len > sizeof(rbuf) - 4)
		return -1;
	/* Determine address family from packet IP header. */
	memcpy(&iph, buf, sizeof(iph));
	af = iph.ip_v == 6 ? OPENBSD_AF_INET6 : OPENBSD_AF_INET;
	/* Prepend address family to packet using OpenBSD constants */
	memcpy(rbuf + 4, buf, len);
	len += 4;
	POKE_U32(rbuf, af);
	ptr = rbuf;
#elif defined(SSH_TUN_COMPAT_AF)
	/* Convert existing address family header to OpenBSD value */
	if (len <= 4)
		return -1;
	af = PEEK_U32(buf);
	/* Put it back */
	POKE_U32(buf, af == AF_INET6 ? OPENBSD_AF_INET6 : OPENBSD_AF_INET);
#endif

	if ((r = sshbuf_put_string(c->input, ptr, len)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	return (0);
}

u_char *
sys_tun_outfilter(struct ssh *ssh, struct Channel *c,
    u_char **data, size_t *dlen)
{
	u_char *buf;
	u_int32_t af;
	int r;

	/* XXX new API is incompatible with this signature. */
	if ((r = sshbuf_get_string(c->output, data, dlen)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	if (*dlen < sizeof(af))
		return (NULL);
	buf = *data;

#if defined(SSH_TUN_PREPEND_AF)
	/* skip address family */
	*dlen -= sizeof(af);
	buf = *data + sizeof(af);
#elif defined(SSH_TUN_COMPAT_AF)
	/* translate address family */
	af = (PEEK_U32(buf) == OPENBSD_AF_INET6) ? AF_INET6 : AF_INET;
	POKE_U32(buf, af);
#endif
	return (buf);
}
#endif /* SSH_TUN_FILTER */
