/**
 * This file is part of Hercules.
 * http://herc.ws - http://github.com/HerculesWS/Hercules
 *
 * Copyright (C) 2012-2016  Hercules Dev Team
 * Copyright (C)  Athena Dev Teams
 *
 * Hercules is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#define HERCULES_CORE

#include "config/core.h" // SHOW_SERVER_STATS
#include "socket.h"

#include "common/HPM.h"
#include "common/cbasetypes.h"
#include "common/conf.h"
#include "common/db.h"
#include "common/memmgr.h"
#include "common/mmo.h"
#include "common/nullpo.h"
#include "common/showmsg.h"
#include "common/strlib.h"
#include "common/timer.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#ifdef SOCKET_EPOLL
#include <sys/epoll.h>
#endif  // SOCKET_EPOLL

#ifdef WIN32
#	include "common/winapi.h"
#else  // WIN32
#	include <arpa/inet.h>
#	include <errno.h>
#	include <net/if.h>
#	include <netdb.h>
#if defined __linux__ || defined __linux
#       include <linux/tcp.h>
#else  // defined __linux__ || defined __linux
#	include <netinet/in.h>
#	include <netinet/tcp.h>
#endif  // defined __linux__ || defined __linux
#	include <sys/ioctl.h>
#	include <sys/socket.h>
#	include <sys/time.h>
#	include <unistd.h>

#ifndef SIOCGIFCONF
#	include <sys/sockio.h> // SIOCGIFCONF on Solaris, maybe others? [Shinomori]
#endif  // SIOCGIFCONF
#ifndef FIONBIO
#	include <sys/filio.h> // FIONBIO on Solaris [FlavioJS]
#endif  // FIONBIO

#ifdef HAVE_SETRLIMIT
#	include <sys/resource.h>
#endif  // HAVE_SETRLIMIT
#endif  // WIN32

/**
 * Socket Interface Source
 **/
struct socket_interface sockt_s;
struct socket_interface *sockt;

struct socket_data **session;

const char *SOCKET_CONF_FILENAME = "conf/common/socket.conf";

#ifdef SEND_SHORTLIST
// Add a fd to the shortlist so that it'll be recognized as a fd that needs
// sending done on it.
void send_shortlist_add_fd(int fd);
// Do pending network sends (and eof handling) from the shortlist.
void send_shortlist_do_sends(void);
#endif  // SEND_SHORTLIST

/////////////////////////////////////////////////////////////////////
#if defined(WIN32)
/////////////////////////////////////////////////////////////////////
// windows portability layer

typedef int socklen_t;

#define sErrno WSAGetLastError()
#define S_ENOTSOCK WSAENOTSOCK
#define S_EWOULDBLOCK WSAEWOULDBLOCK
#define S_EINTR WSAEINTR
#define S_ECONNABORTED WSAECONNABORTED

#define SHUT_RD   SD_RECEIVE
#define SHUT_WR   SD_SEND
#define SHUT_RDWR SD_BOTH

// global array of sockets (emulating linux)
// fd is the position in the array
static SOCKET sock_arr[FD_SETSIZE];
static int sock_arr_len = 0;

/// Returns the socket associated with the target fd.
///
/// @param fd Target fd.
/// @return Socket
#define fd2sock(fd) sock_arr[fd]

/// Returns the first fd associated with the socket.
/// Returns -1 if the socket is not found.
///
/// @param s Socket
/// @return Fd or -1
int sock2fd(SOCKET s)
{
	int fd;

	// search for the socket
	for( fd = 1; fd < sock_arr_len; ++fd )
		if( sock_arr[fd] == s )
			break;// found the socket
	if( fd == sock_arr_len )
		return -1;// not found
	return fd;
}

/// Inserts the socket into the global array of sockets.
/// Returns a new fd associated with the socket.
/// If there are too many sockets it closes the socket, sets an error and
//  returns -1 instead.
/// Since fd 0 is reserved, it returns values in the range [1,FD_SETSIZE[.
///
/// @param s Socket
/// @return New fd or -1
int sock2newfd(SOCKET s)
{
	int fd;

	// find an empty position
	for( fd = 1; fd < sock_arr_len; ++fd )
		if( sock_arr[fd] == INVALID_SOCKET )
			break;// empty position
	if( fd == ARRAYLENGTH(sock_arr) )
	{// too many sockets
		closesocket(s);
		WSASetLastError(WSAEMFILE);
		return -1;
	}
	sock_arr[fd] = s;
	if( sock_arr_len <= fd )
		sock_arr_len = fd+1;
	return fd;
}

int sAccept(int fd, struct sockaddr* addr, int* addrlen)
{
	SOCKET s;

	// accept connection
	s = accept(fd2sock(fd), addr, addrlen);
	if( s == INVALID_SOCKET )
		return -1;// error
	return sock2newfd(s);
}

int sClose(int fd)
{
	int ret = closesocket(fd2sock(fd));
	fd2sock(fd) = INVALID_SOCKET;
	return ret;
}

int sSocket(int af, int type, int protocol)
{
	SOCKET s;

	// create socket
	s = socket(af,type,protocol);
	if( s == INVALID_SOCKET )
		return -1;// error
	return sock2newfd(s);
}

char* sErr(int code)
{
	static char sbuf[512];
	// strerror does not handle socket codes
	if( FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_IGNORE_INSERTS, NULL,
			code, MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT), (LPTSTR)&sbuf, sizeof(sbuf), NULL) == 0 )
		snprintf(sbuf, sizeof(sbuf), "unknown error");
	return sbuf;
}

#define sBind(fd,name,namelen)                      bind(fd2sock(fd),(name),(namelen))
#define sConnect(fd,name,namelen)                   connect(fd2sock(fd),(name),(namelen))
#define sIoctl(fd,cmd,argp)                         ioctlsocket(fd2sock(fd),(cmd),(argp))
#define sListen(fd,backlog)                         listen(fd2sock(fd),(backlog))
#define sRecv(fd,buf,len,flags)                     recv(fd2sock(fd),(buf),(len),(flags))
#define sSelect                                     select
#define sSend(fd,buf,len,flags)                     send(fd2sock(fd),(buf),(len),(flags))
#define sSetsockopt(fd,level,optname,optval,optlen) setsockopt(fd2sock(fd),(level),(optname),(optval),(optlen))
#define sShutdown(fd,how)                           shutdown(fd2sock(fd),(how))
#define sFD_SET(fd,set)                             FD_SET(fd2sock(fd),(set))
#define sFD_CLR(fd,set)                             FD_CLR(fd2sock(fd),(set))
#define sFD_ISSET(fd,set)                           FD_ISSET(fd2sock(fd),(set))
#define sFD_ZERO                                    FD_ZERO

/////////////////////////////////////////////////////////////////////
#else  // defined(WIN32)
/////////////////////////////////////////////////////////////////////
// nix portability layer

#define SOCKET_ERROR (-1)

#define sErrno errno
#define S_ENOTSOCK EBADF
#define S_EWOULDBLOCK EAGAIN
#define S_EINTR EINTR
#define S_ECONNABORTED ECONNABORTED

#define sAccept accept
#define sClose close
#define sSocket socket
#define sErr strerror

#define sBind bind
#define sConnect connect
#define sIoctl ioctl
#define sListen listen
#define sRecv recv
#define sSelect select
#define sSend send
#define sSetsockopt setsockopt
#define sShutdown shutdown
#define sFD_SET FD_SET
#define sFD_CLR FD_CLR
#define sFD_ISSET FD_ISSET
#define sFD_ZERO FD_ZERO

/////////////////////////////////////////////////////////////////////
#endif  // defined(WIN32)
/////////////////////////////////////////////////////////////////////

#ifndef MSG_NOSIGNAL
	#define MSG_NOSIGNAL 0
#endif  // MSG_NOSIGNAL

#ifndef SOCKET_EPOLL
// Select based Event Dispatcher:
fd_set readfds;

#else  // SOCKET_EPOLL
// Epoll based Event Dispatcher:
static int epoll_maxevents = (FD_SETSIZE / 2);
static int epfd = SOCKET_ERROR;
static struct epoll_event epevent;
static struct epoll_event *epevents = NULL;

#endif  // SOCKET_EPOLL

// Maximum packet size in bytes, which the client is able to handle.
// Larger packets cause a buffer overflow and stack corruption.
#if PACKETVER >= 20131223
static size_t socket_max_client_packet = 0xFFFF;
#else  // PACKETVER >= 20131223
static size_t socket_max_client_packet = 0x6000;
#endif  // PACKETVER >= 20131223

#ifdef SHOW_SERVER_STATS
// Data I/O statistics
static size_t socket_data_i = 0, socket_data_ci = 0, socket_data_qi = 0;
static size_t socket_data_o = 0, socket_data_co = 0, socket_data_qo = 0;
static time_t socket_data_last_tick = 0;
#endif  // SHOW_SERVER_STATS

// initial recv buffer size (this will also be the max. size)
// biggest known packet: S 0153 <len>.w <emblem data>.?B -> 24x24 256 color .bmp (0153 + len.w + 1618/1654/1756 bytes)
#define RFIFO_SIZE (2*1024)
// initial send buffer size (will be resized as needed)
#define WFIFO_SIZE (16*1024)

// Maximum size of pending data in the write fifo. (for non-server connections)
// The connection is closed if it goes over the limit.
#define WFIFO_MAX (1*1024*1024)

#ifdef SEND_SHORTLIST
int send_shortlist_array[FD_SETSIZE];// we only support FD_SETSIZE sockets, limit the array to that
int send_shortlist_count = 0;// how many fd's are in the shortlist
uint32 send_shortlist_set[(FD_SETSIZE+31)/32];// to know if specific fd's are already in the shortlist
#endif  // SEND_SHORTLIST

static int create_session(int fd, RecvFunc func_recv, SendFunc func_send, ParseFunc func_parse);

#ifndef MINICORE
	int ip_rules = 1;
	static int connect_check(uint32 ip);
#endif  // MINICORE

const char* error_msg(void)
{
	static char buf[512];
	int code = sErrno;
	snprintf(buf, sizeof(buf), "error %d: %s", code, sErr(code));
	return buf;
}

/*======================================
 * CORE : Default processing functions
 *--------------------------------------*/
int null_recv(int fd) { return 0; }
int null_send(int fd) { return 0; }
int null_parse(int fd) { return 0; }

ParseFunc default_func_parse = null_parse;

void set_defaultparse(ParseFunc defaultparse)
{
	default_func_parse = defaultparse;
}

/*======================================
 * CORE : Socket options
 *--------------------------------------*/
void set_nonblocking(int fd, unsigned long yes)
{
	// FIONBIO Use with a nonzero argp parameter to enable the nonblocking mode of socket s.
	// The argp parameter is zero if nonblocking is to be disabled.
	if( sIoctl(fd, FIONBIO, &yes) != 0 )
		ShowError("set_nonblocking: Failed to set socket #%d to non-blocking mode (%s) - Please report this!!!\n", fd, error_msg());
}

/**
 * Sets the options for a socket.
 *
 * @param fd  The socket descriptor
 * @param opt Optional, additional options to set (Can be NULL).
 */
void setsocketopts(int fd, struct hSockOpt *opt)
{
#if defined(WIN32)
	BOOL yes = TRUE;
#else // not WIN32
	int yes = 1;
#endif // WIN32
	struct linger lopt = { 0 };

	// Note: We cast the fourth argument to (char *) because, while in UNIX
	// it takes a const void *, in Windows it takes a const char *.
#if !defined(WIN32)
	// set SO_REAUSEADDR to true, unix only. on windows this option causes
	// the previous owner of the socket to give up, which is not desirable
	// in most cases, neither compatible with unix.
	if (sSetsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&yes, sizeof(yes)))
		ShowWarning("setsocketopts: Unable to set SO_REUSEADDR mode for connection #%d!\n", fd);
#ifdef SO_REUSEPORT
	if (sSetsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (char *)&yes, sizeof(yes)))
		ShowWarning("setsocketopts: Unable to set SO_REUSEPORT mode for connection #%d!\n", fd);
#endif // SO_REUSEPORT
#endif // WIN32

	// Set the socket into no-delay mode; otherwise packets get delayed for up to 200ms, likely creating server-side lag.
	// The RO protocol is mainly single-packet request/response, plus the FIFO model already does packet grouping anyway.
	if (sSetsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *)&yes, sizeof(yes)))
		ShowWarning("setsocketopts: Unable to set TCP_NODELAY mode for connection #%d!\n", fd);

	if (opt && opt->setTimeo) {
#if defined(WIN32)
		DWORD timeout = 5000; // https://msdn.microsoft.com/en-us/library/windows/desktop/ms740476(v=vs.85).aspx
#else // not WIN32
		struct timeval timeout = { 0 };
		timeout.tv_sec = 5;
#endif // WIN32

		if (sSetsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)))
			ShowWarning("setsocketopts: Unable to set SO_RCVTIMEO for connection #%d!\n", fd);
		if (sSetsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout)))
			ShowWarning("setsocketopts: Unable to set SO_SNDTIMEO for connection #%d!\n", fd);
	}

	// force the socket into no-wait, graceful-close mode (should be the default, but better make sure)
	//(http://msdn.microsoft.com/library/default.asp?url=/library/en-us/winsock/winsock/closesocket_2.asp)
	lopt.l_onoff = 0; // SO_DONTLINGER
	lopt.l_linger = 0; // Do not care
	if (sSetsockopt(fd, SOL_SOCKET, SO_LINGER, (char *)&lopt, sizeof(lopt)))
		ShowWarning("setsocketopts: Unable to set SO_LINGER mode for connection #%d!\n", fd);

#ifdef TCP_THIN_LINEAR_TIMEOUTS
	if (sSetsockopt(fd, IPPROTO_TCP, TCP_THIN_LINEAR_TIMEOUTS, (char *)&yes, sizeof(yes)))
		ShowWarning("setsocketopts: Unable to set TCP_THIN_LINEAR_TIMEOUTS mode for connection #%d!\n", fd);
#endif  // TCP_THIN_LINEAR_TIMEOUTS
#ifdef TCP_THIN_DUPACK
	if (sSetsockopt(fd, IPPROTO_TCP, TCP_THIN_DUPACK, (char *)&yes, sizeof(yes)))
		ShowWarning("setsocketopts: Unable to set TCP_THIN_DUPACK mode for connection #%d!\n", fd);
#endif  // TCP_THIN_DUPACK
}

/*======================================
 * CORE : Socket Sub Function
 *--------------------------------------*/
void set_eof(int fd)
{
	if (sockt->session_is_active(fd)) {
#ifdef SEND_SHORTLIST
		// Add this socket to the shortlist for eof handling.
		send_shortlist_add_fd(fd);
#endif  // SEND_SHORTLIST
		sockt->session[fd]->flag.eof = 1;
	}
}

int recv_to_fifo(int fd)
{
	ssize_t len;

	if (!sockt->session_is_active(fd))
		return -1;

	len = sRecv(fd, (char *) sockt->session[fd]->rdata + sockt->session[fd]->rdata_size, (int)RFIFOSPACE(fd), 0);

	if( len == SOCKET_ERROR )
	{//An exception has occurred
		if( sErrno != S_EWOULDBLOCK ) {
			//ShowDebug("recv_to_fifo: %s, closing connection #%d\n", error_msg(), fd);
			sockt->eof(fd);
		}
		return 0;
	}

	if( len == 0 )
	{//Normal connection end.
		sockt->eof(fd);
		return 0;
	}

	sockt->session[fd]->rdata_size += len;
	sockt->session[fd]->rdata_tick = sockt->last_tick;
#ifdef SHOW_SERVER_STATS
	socket_data_i += len;
	socket_data_qi += len;
	if (!sockt->session[fd]->flag.server)
	{
		socket_data_ci += len;
	}
#endif  // SHOW_SERVER_STATS
	return 0;
}

int send_from_fifo(int fd)
{
	ssize_t len;

	if (!sockt->session_is_valid(fd))
		return -1;

	if( sockt->session[fd]->wdata_size == 0 )
		return 0; // nothing to send

	len = sSend(fd, (const char *) sockt->session[fd]->wdata, (int)sockt->session[fd]->wdata_size, MSG_NOSIGNAL);

	if( len == SOCKET_ERROR )
	{ //An exception has occurred
		if( sErrno != S_EWOULDBLOCK ) {
			//ShowDebug("send_from_fifo: %s, ending connection #%d\n", error_msg(), fd);
#ifdef SHOW_SERVER_STATS
			socket_data_qo -= sockt->session[fd]->wdata_size;
#endif  // SHOW_SERVER_STATS
			sockt->session[fd]->wdata_size = 0; //Clear the send queue as we can't send anymore. [Skotlex]
			sockt->eof(fd);
		}
		return 0;
	}

	if( len > 0 )
	{
		// some data could not be transferred?
		// shift unsent data to the beginning of the queue
		if( (size_t)len < sockt->session[fd]->wdata_size )
			memmove(sockt->session[fd]->wdata, sockt->session[fd]->wdata + len, sockt->session[fd]->wdata_size - len);

		sockt->session[fd]->wdata_size -= len;
#ifdef SHOW_SERVER_STATS
		socket_data_o += len;
		socket_data_qo -= len;
		if (!sockt->session[fd]->flag.server)
		{
			socket_data_co += len;
		}
#endif  // SHOW_SERVER_STATS
	}

	return 0;
}

/// Best effort - there's no warranty that the data will be sent.
void flush_fifo(int fd)
{
	if(sockt->session[fd] != NULL)
		sockt->session[fd]->func_send(fd);
}

void flush_fifos(void)
{
	int i;
	for(i = 1; i < sockt->fd_max; i++)
		sockt->flush(i);
}

/*======================================
 * CORE : Connection functions
 *--------------------------------------*/
int connect_client(int listen_fd)
{
	int fd;
	struct sockaddr_in client_address;
	socklen_t len;

	len = sizeof(client_address);

	fd = sAccept(listen_fd, (struct sockaddr*)&client_address, &len);
	if ( fd == -1 ) {
		ShowError("connect_client: accept failed (%s)!\n", error_msg());
		return -1;
	}
	if( fd == 0 ) { // reserved
		ShowError("connect_client: Socket #0 is reserved - Please report this!!!\n");
		sClose(fd);
		return -1;
	}
	if( fd >= FD_SETSIZE ) { // socket number too big
		ShowError("connect_client: New socket #%d is greater than can we handle! Increase the value of FD_SETSIZE (currently %d) for your OS to fix this!\n", fd, FD_SETSIZE);
		sClose(fd);
		return -1;
	}

	setsocketopts(fd,NULL);
	sockt->set_nonblocking(fd, 1);

#ifndef MINICORE
	if( ip_rules && !connect_check(ntohl(client_address.sin_addr.s_addr)) ) {
		sockt->close(fd);
		return -1;
	}
#endif  // MINICORE

#ifndef SOCKET_EPOLL
	// Select Based Event Dispatcher
	sFD_SET(fd,&readfds);

#else  // SOCKET_EPOLL
	// Epoll based Event Dispatcher
	epevent.data.fd = fd;
	epevent.events = EPOLLIN;

	if(epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &epevent) == SOCKET_ERROR){
		ShowError("connect_client: New Socket #%d failed to add to epoll event dispatcher: %s\n", fd, error_msg());
		sClose(fd);
		return -1;
	}

#endif  // SOCKET_EPOLL

	if( sockt->fd_max <= fd ) sockt->fd_max = fd + 1;

	create_session(fd, recv_to_fifo, send_from_fifo, default_func_parse);
	sockt->session[fd]->client_addr = ntohl(client_address.sin_addr.s_addr);

	return fd;
}

int make_listen_bind(uint32 ip, uint16 port)
{
	struct sockaddr_in server_address = { 0 };
	int fd;
	int result;

	fd = sSocket(AF_INET, SOCK_STREAM, 0);

	if( fd == -1 ) {
		ShowError("make_listen_bind: socket creation failed (%s)!\n", error_msg());
		exit(EXIT_FAILURE);
	}
	if( fd == 0 ) { // reserved
		ShowError("make_listen_bind: Socket #0 is reserved - Please report this!!!\n");
		sClose(fd);
		return -1;
	}
	if( fd >= FD_SETSIZE ) { // socket number too big
		ShowError("make_listen_bind: New socket #%d is greater than can we handle! Increase the value of FD_SETSIZE (currently %d) for your OS to fix this!\n", fd, FD_SETSIZE);
		sClose(fd);
		return -1;
	}

	setsocketopts(fd,NULL);
	sockt->set_nonblocking(fd, 1);

	server_address.sin_family      = AF_INET;
	server_address.sin_addr.s_addr = htonl(ip);
	server_address.sin_port        = htons(port);

	result = sBind(fd, (struct sockaddr*)&server_address, sizeof(server_address));
	if( result == SOCKET_ERROR ) {
		ShowError("make_listen_bind: bind failed (socket #%d, %s)!\n", fd, error_msg());
		exit(EXIT_FAILURE);
	}
	result = sListen(fd,5);
	if( result == SOCKET_ERROR ) {
		ShowError("make_listen_bind: listen failed (socket #%d, %s)!\n", fd, error_msg());
		exit(EXIT_FAILURE);
	}


#ifndef SOCKET_EPOLL
	// Select Based Event Dispatcher
	sFD_SET(fd,&readfds);

#else  // SOCKET_EPOLL
	// Epoll based Event Dispatcher
	epevent.data.fd = fd;
	epevent.events = EPOLLIN;

	if(epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &epevent) == SOCKET_ERROR){
		ShowError("make_listen_bind: failed to add listener socket #%d to epoll event dispatcher: %s\n", fd, error_msg());
		sClose(fd);
		exit(EXIT_FAILURE);
	}

#endif  // SOCKET_EPOLL

	if(sockt->fd_max <= fd) sockt->fd_max = fd + 1;


	create_session(fd, connect_client, null_send, null_parse);
	sockt->session[fd]->client_addr = 0; // just listens
	sockt->session[fd]->rdata_tick = 0; // disable timeouts on this socket

	return fd;
}

int make_connection(uint32 ip, uint16 port, struct hSockOpt *opt)
{
	struct sockaddr_in remote_address = { 0 };
	int fd;
	int result;

	fd = sSocket(AF_INET, SOCK_STREAM, 0);

	if (fd == -1) {
		ShowError("make_connection: socket creation failed (%s)!\n", error_msg());
		return -1;
	}
	if( fd == 0 ) {// reserved
		ShowError("make_connection: Socket #0 is reserved - Please report this!!!\n");
		sClose(fd);
		return -1;
	}
	if( fd >= FD_SETSIZE ) {// socket number too big
		ShowError("make_connection: New socket #%d is greater than can we handle! Increase the value of FD_SETSIZE (currently %d) for your OS to fix this!\n", fd, FD_SETSIZE);
		sClose(fd);
		return -1;
	}

	setsocketopts(fd,opt);

	remote_address.sin_family      = AF_INET;
	remote_address.sin_addr.s_addr = htonl(ip);
	remote_address.sin_port        = htons(port);

	if( !( opt && opt->silent ) )
		ShowStatus("Connecting to %u.%u.%u.%u:%i\n", CONVIP(ip), port);

	result = sConnect(fd, (struct sockaddr *)(&remote_address), sizeof(struct sockaddr_in));
	if( result == SOCKET_ERROR ) {
		if( !( opt && opt->silent ) )
			ShowError("make_connection: connect failed (socket #%d, %s)!\n", fd, error_msg());
		sockt->close(fd);
		return -1;
	}
	//Now the socket can be made non-blocking. [Skotlex]
	sockt->set_nonblocking(fd, 1);


#ifndef SOCKET_EPOLL
	// Select Based Event Dispatcher
	sFD_SET(fd,&readfds);

#else  // SOCKET_EPOLL
	// Epoll based Event Dispatcher
	epevent.data.fd = fd;
	epevent.events = EPOLLIN;

	if(epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &epevent) == SOCKET_ERROR){
		ShowError("make_connection: failed to add socket #%d to epoll event dispatcher: %s\n", fd, error_msg());
		sClose(fd);
		return -1;
	}

#endif  // SOCKET_EPOLL

	if(sockt->fd_max <= fd) sockt->fd_max = fd + 1;

	create_session(fd, recv_to_fifo, send_from_fifo, default_func_parse);
	sockt->session[fd]->client_addr = ntohl(remote_address.sin_addr.s_addr);

	return fd;
}

static int create_session(int fd, RecvFunc func_recv, SendFunc func_send, ParseFunc func_parse)
{
	CREATE(sockt->session[fd], struct socket_data, 1);
	CREATE(sockt->session[fd]->rdata, unsigned char, RFIFO_SIZE);
	CREATE(sockt->session[fd]->wdata, unsigned char, WFIFO_SIZE);
	sockt->session[fd]->max_rdata  = RFIFO_SIZE;
	sockt->session[fd]->max_wdata  = WFIFO_SIZE;
	sockt->session[fd]->func_recv  = func_recv;
	sockt->session[fd]->func_send  = func_send;
	sockt->session[fd]->func_parse = func_parse;
	sockt->session[fd]->rdata_tick = sockt->last_tick;
	sockt->session[fd]->session_data = NULL;
	sockt->session[fd]->hdata = NULL;
	return 0;
}

static void delete_session(int fd)
{
	if (sockt->session_is_valid(fd)) {
#ifdef SHOW_SERVER_STATS
		socket_data_qi -= sockt->session[fd]->rdata_size - sockt->session[fd]->rdata_pos;
		socket_data_qo -= sockt->session[fd]->wdata_size;
#endif  // SHOW_SERVER_STATS
		aFree(sockt->session[fd]->rdata);
		aFree(sockt->session[fd]->wdata);
		if( sockt->session[fd]->session_data )
			aFree(sockt->session[fd]->session_data);
		HPM->data_store_destroy(&sockt->session[fd]->hdata);
		aFree(sockt->session[fd]);
		sockt->session[fd] = NULL;
	}
}

int realloc_fifo(int fd, unsigned int rfifo_size, unsigned int wfifo_size)
{
	if (!sockt->session_is_valid(fd))
		return 0;

	if( sockt->session[fd]->max_rdata != rfifo_size && sockt->session[fd]->rdata_size < rfifo_size) {
		RECREATE(sockt->session[fd]->rdata, unsigned char, rfifo_size);
		sockt->session[fd]->max_rdata  = rfifo_size;
	}

	if( sockt->session[fd]->max_wdata != wfifo_size && sockt->session[fd]->wdata_size < wfifo_size) {
		RECREATE(sockt->session[fd]->wdata, unsigned char, wfifo_size);
		sockt->session[fd]->max_wdata  = wfifo_size;
	}
	return 0;
}

int realloc_writefifo(int fd, size_t addition)
{
	size_t newsize;

	if (!sockt->session_is_valid(fd)) // might not happen
		return 0;

	if (sockt->session[fd]->wdata_size + addition  > sockt->session[fd]->max_wdata) {
		// grow rule; grow in multiples of WFIFO_SIZE
		newsize = WFIFO_SIZE;
		while( sockt->session[fd]->wdata_size + addition > newsize ) newsize += WFIFO_SIZE;
	} else if (sockt->session[fd]->max_wdata >= (size_t)2*(sockt->session[fd]->flag.server?FIFOSIZE_SERVERLINK:WFIFO_SIZE)
	       && (sockt->session[fd]->wdata_size+addition)*4 < sockt->session[fd]->max_wdata
	) {
		// shrink rule, shrink by 2 when only a quarter of the fifo is used, don't shrink below nominal size.
		newsize = sockt->session[fd]->max_wdata / 2;
	} else {
		// no change
		return 0;
	}

	RECREATE(sockt->session[fd]->wdata, unsigned char, newsize);
	sockt->session[fd]->max_wdata  = newsize;

	return 0;
}

/// advance the RFIFO cursor (marking 'len' bytes as processed)
int rfifoskip(int fd, size_t len)
{
	struct socket_data *s;

	if (!sockt->session_is_active(fd))
		return 0;

	s = sockt->session[fd];

	if (s->rdata_size < s->rdata_pos + len) {
		ShowError("RFIFOSKIP: skipped past end of read buffer! Adjusting from %"PRIuS" to %"PRIuS" (session #%d)\n", len, RFIFOREST(fd), fd);
		len = RFIFOREST(fd);
	}

	s->rdata_pos = s->rdata_pos + len;
#ifdef SHOW_SERVER_STATS
	socket_data_qi -= len;
#endif  // SHOW_SERVER_STATS
	return 0;
}
		
/// advance the WFIFO cursor (marking 'len' bytes for sending)
int wfifoset(int fd, size_t len)
{
	size_t newreserve;
	struct socket_data* s;

	if (!sockt->session_is_valid(fd))
		return 0;
	s = sockt->session[fd];
	if (s == NULL || s->wdata == NULL)
		return 0;

	// we have written len bytes to the buffer already before calling WFIFOSET
	if (s->wdata_size+len > s->max_wdata) {
		// actually there was a buffer overflow already
		uint32 ip = s->client_addr;
		ShowFatalError("WFIFOSET: Write Buffer Overflow. Connection %d (%u.%u.%u.%u) has written %u bytes on a %u/%u bytes buffer.\n", fd, CONVIP(ip), (unsigned int)len, (unsigned int)s->wdata_size, (unsigned int)s->max_wdata);
		ShowDebug("Likely command that caused it: 0x%x\n", (*(uint16*)(s->wdata + s->wdata_size)));
		// no other chance, make a better fifo model
		exit(EXIT_FAILURE);
	}

	if( len > 0xFFFF )
	{
		// dynamic packets allow up to UINT16_MAX bytes (<packet_id>.W <packet_len>.W ...)
		// all known fixed-size packets are within this limit, so use the same limit
		ShowFatalError("WFIFOSET: Packet 0x%x is too big. (len=%u, max=%u)\n", (*(uint16*)(s->wdata + s->wdata_size)), (unsigned int)len, 0xFFFFU);
		exit(EXIT_FAILURE);
	}
	else if( len == 0 )
	{
		// abuses the fact, that the code that did WFIFOHEAD(fd,0), already wrote
		// the packet type into memory, even if it could have overwritten vital data
		// this can happen when a new packet was added on map-server, but packet len table was not updated
		ShowWarning("WFIFOSET: Attempted to send zero-length packet, most likely 0x%04x (please report this).\n", WFIFOW(fd,0));
		return 0;
	}

	if( !s->flag.server ) {

		if (len > socket_max_client_packet) { // see declaration of socket_max_client_packet for details
			ShowError("WFIFOSET: Dropped too large client packet 0x%04x (length=%"PRIuS", max=%"PRIuS").\n",
			          WFIFOW(fd,0), len, socket_max_client_packet);
			return 0;
		}

	}
	// Gepard Shield
	if (is_gepard_active == true && SERVER_TYPE != SERVER_TYPE_CHAR)
	{
		gepard_process_packet(fd, s->wdata + s->wdata_size, len, &s->send_crypt);
	}
	// Gepard Shield
	s->wdata_size += len;
#ifdef SHOW_SERVER_STATS
	socket_data_qo += len;
#endif  // SHOW_SERVER_STATS
	//If the interserver has 200% of its normal size full, flush the data.
	if( s->flag.server && s->wdata_size >= 2*FIFOSIZE_SERVERLINK )
		sockt->flush(fd);

	// always keep a WFIFO_SIZE reserve in the buffer
	// For inter-server connections, let the reserve be 1/4th of the link size.
	newreserve = s->flag.server ? FIFOSIZE_SERVERLINK / 4 : WFIFO_SIZE;

	// readjust the buffer to include the chosen reserve
	sockt->realloc_writefifo(fd, newreserve);

#ifdef SEND_SHORTLIST
	send_shortlist_add_fd(fd);
#endif  // SEND_SHORTLIST

	return 0;
}

int do_sockets(int next)
{
#ifndef SOCKET_EPOLL
	fd_set rfd;
	struct timeval timeout;
#endif  // SOCKET_EPOLL
	int ret,i;

	// PRESEND Timers are executed before do_sendrecv and can send packets and/or set sessions to eof.
	// Send remaining data and process client-side disconnects here.
#ifdef SEND_SHORTLIST
	send_shortlist_do_sends();
#else  // SEND_SHORTLIST
	for (i = 1; i < sockt->fd_max; i++) {
		if (sockt->session[i] == NULL)
			continue;

		if (sockt->session[i]->wdata_size > 0)
			sockt->session[i]->func_send(i);
	}
#endif  // SEND_SHORTLIST

#ifndef SOCKET_EPOLL
	// Select based Event Dispatcher:

	// can timeout until the next tick
	timeout.tv_sec  = next/1000;
	timeout.tv_usec = next%1000*1000;

	memcpy(&rfd, &readfds, sizeof(rfd));
	ret = sSelect(sockt->fd_max, &rfd, NULL, NULL, &timeout);

	if( ret == SOCKET_ERROR )
	{
		if( sErrno != S_EINTR )
		{
			ShowFatalError("do_sockets: select() failed, %s!\n", error_msg());
			exit(EXIT_FAILURE);
		}
		return 0; // interrupted by a signal, just loop and try again
	}
#else  // SOCKET_EPOLL
	// Epoll based Event Dispatcher

	ret = epoll_wait(epfd, epevents, epoll_maxevents, next);
	if(ret == SOCKET_ERROR)
	{
		if( sErrno != S_EINTR )
		{
			ShowFatalError("do_sockets: epoll_wait() failed, %s!\n", error_msg());
			exit(EXIT_FAILURE);
		}
		return 0; // interrupted by a signal, just loop and try again
	}
#endif  // SOCKET_EPOLL

	sockt->last_tick = time(NULL);

#if defined(WIN32)
	// on windows, enumerating all members of the fd_set is way faster if we access the internals
	for( i = 0; i < (int)rfd.fd_count; ++i )
	{
		int fd = sock2fd(rfd.fd_array[i]);
		if( sockt->session[fd] )
			sockt->session[fd]->func_recv(fd);
	}
#elif defined(SOCKET_EPOLL)
	// epoll based selection

	for( i = 0; i < ret; i++ )
	{
		struct epoll_event *it = &epevents[i];
		struct socket_data *sock = sockt->session[ it->data.fd ];

		if(!sock)
			continue;

		if ((it->events & EPOLLERR) ||
			(it->events & EPOLLHUP) ||
			(!(it->events & EPOLLIN)))
		{
			// Got Error on this connection
			sockt->eof( it->data.fd );

		} else if (it->events & EPOLLIN) {
			// data wainting
			sock->func_recv( it->data.fd );

		}

	}

#else  // defined(SOCKET_EPOLL)
	// otherwise assume that the fd_set is a bit-array and enumerate it in a standard way
	for( i = 1; ret && i < sockt->fd_max; ++i )
	{
		if(sFD_ISSET(i,&rfd) && sockt->session[i])
		{
			sockt->session[i]->func_recv(i);
			--ret;
		}
	}
#endif  // defined(SOCKET_EPOLL)

	// POSTSEND Send remaining data and handle eof sessions.
#ifdef SEND_SHORTLIST
	send_shortlist_do_sends();
#else  // SEND_SHORTLIST
	for (i = 1; i < sockt->fd_max; i++)
	{
		if(!sockt->session[i])
			continue;

		if(sockt->session[i]->wdata_size)
			sockt->session[i]->func_send(i);

		if (sockt->session[i]->flag.eof) { //func_send can't free a session, this is safe.
			//Finally, even if there is no data to parse, connections signaled eof should be closed, so we call parse_func [Skotlex]
			sockt->session[i]->func_parse(i); //This should close the session immediately.
		}
	}
#endif  // SEND_SHORTLIST

	// parse input data on each socket
	for(i = 1; i < sockt->fd_max; i++)
	{
		if(!sockt->session[i])
			continue;

		if (sockt->session[i]->rdata_tick && DIFF_TICK(sockt->last_tick, sockt->session[i]->rdata_tick) > sockt->stall_time) {
			if( sockt->session[i]->flag.server ) {/* server is special */
				if( sockt->session[i]->flag.ping != 2 )/* only update if necessary otherwise it'd resend the ping unnecessarily */
					sockt->session[i]->flag.ping = 1;
			} else {
				ShowInfo("Session #%d timed out\n", i);
				sockt->eof(i);
			}
		}

		sockt->session[i]->func_parse(i);

		if(!sockt->session[i])
			continue;

		RFIFOFLUSH(i);
		// after parse, check client's RFIFO size to know if there is an invalid packet (too big and not parsed)
		if (sockt->session[i]->rdata_size == sockt->session[i]->max_rdata) {
			sockt->eof(i);
			continue;
		}
	}

#ifdef SHOW_SERVER_STATS
	if (sockt->last_tick != socket_data_last_tick)
	{
		char buf[1024];

		sprintf(buf, "In: %.03f kB/s (%.03f kB/s, Q: %.03f kB) | Out: %.03f kB/s (%.03f kB/s, Q: %.03f kB) | RAM: %.03f MB", socket_data_i/1024., socket_data_ci/1024., socket_data_qi/1024., socket_data_o/1024., socket_data_co/1024., socket_data_qo/1024., iMalloc->usage()/1024.);
#ifdef _WIN32
		SetConsoleTitle(buf);
#else  // _WIN32
		ShowMessage("\033[s\033[1;1H\033[2K%s\033[u", buf);
#endif  // _WIN32
		socket_data_last_tick = sockt->last_tick;
		socket_data_i = socket_data_ci = 0;
		socket_data_o = socket_data_co = 0;
	}
#endif  // SHOW_SERVER_STATS

	return 0;
}

//////////////////////////////
#ifndef MINICORE
//////////////////////////////
// IP rules and DDoS protection

struct connect_history {
	uint32 ip;
	int64 tick;
	int count;
	unsigned ddos : 1;
};

struct access_control {
	uint32 ip;
	uint32 mask;
};

VECTOR_STRUCT_DECL(access_control_list, struct access_control);

enum aco {
	ACO_DENY_ALLOW,
	ACO_ALLOW_DENY,
	ACO_MUTUAL_FAILURE
};

static struct access_control_list access_allow;
static struct access_control_list access_deny;
static int access_order    = ACO_DENY_ALLOW;
static int access_debug    = 0;
static int ddos_count      = 10;
static int ddos_interval   = 3*1000;
static int ddos_autoreset  = 10*60*1000;
struct DBMap *connect_history = NULL;

static int connect_check_(uint32 ip);

/// Verifies if the IP can connect. (with debug info)
/// @see connect_check_()
static int connect_check(uint32 ip)
{
	int result = connect_check_(ip);
	if( access_debug ) {
		ShowInfo("connect_check: Connection from %u.%u.%u.%u %s\n", CONVIP(ip),result ? "allowed." : "denied!");
	}
	return result;
}

/// Verifies if the IP can connect.
///  0      : Connection Rejected
///  1 or 2 : Connection Accepted
static int connect_check_(uint32 ip)
{
	struct connect_history *hist = NULL;
	int i;
	int is_allowip = 0;
	int is_denyip = 0;
	int connect_ok = 0;

	// Search the allow list
	for (i = 0; i < VECTOR_LENGTH(access_allow); ++i) {
		struct access_control *entry = &VECTOR_INDEX(access_allow, i);
		if (SUBNET_MATCH(ip, entry->ip, entry->mask)) {
			if (access_debug) {
				ShowInfo("connect_check: Found match from allow list:%u.%u.%u.%u IP:%u.%u.%u.%u Mask:%u.%u.%u.%u\n",
					CONVIP(ip),
					CONVIP(entry->ip),
					CONVIP(entry->mask));
			}
			is_allowip = 1;
			break;
		}
	}
	// Search the deny list
	for (i = 0; i < VECTOR_LENGTH(access_deny); ++i) {
		struct access_control *entry = &VECTOR_INDEX(access_deny, i);
		if (SUBNET_MATCH(ip, entry->ip, entry->mask)) {
			if (access_debug) {
				ShowInfo("connect_check: Found match from deny list:%u.%u.%u.%u IP:%u.%u.%u.%u Mask:%u.%u.%u.%u\n",
					CONVIP(ip),
					CONVIP(entry->ip),
					CONVIP(entry->mask));
			}
			is_denyip = 1;
			break;
		}
	}
	// Decide connection status
	//  0 : Reject
	//  1 : Accept
	//  2 : Unconditional Accept (accepts even if flagged as DDoS)
	switch(access_order) {
		case ACO_DENY_ALLOW:
		default:
			if( is_denyip )
				connect_ok = 0; // Reject
			else if( is_allowip )
				connect_ok = 2; // Unconditional Accept
			else
				connect_ok = 1; // Accept
			break;
		case ACO_ALLOW_DENY:
			if( is_allowip )
				connect_ok = 2; // Unconditional Accept
			else if( is_denyip )
				connect_ok = 0; // Reject
			else
				connect_ok = 1; // Accept
			break;
		case ACO_MUTUAL_FAILURE:
			if( is_allowip && !is_denyip )
				connect_ok = 2; // Unconditional Accept
			else
				connect_ok = 0; // Reject
			break;
	}

	// Inspect connection history
	if( ( hist = uidb_get(connect_history, ip)) ) { //IP found
		if( hist->ddos ) {// flagged as DDoS
			return (connect_ok == 2 ? 1 : 0);
		} else if( DIFF_TICK(timer->gettick(),hist->tick) < ddos_interval ) {// connection within ddos_interval
				hist->tick = timer->gettick();
				if( ++hist->count >= ddos_count ) {// DDoS attack detected
					hist->ddos = 1;
					ShowWarning("connect_check: DDoS Attack detected from %u.%u.%u.%u!\n", CONVIP(ip));
					return (connect_ok == 2 ? 1 : 0);
				}
				return connect_ok;
		} else {// not within ddos_interval, clear data
			hist->tick  = timer->gettick();
			hist->count = 0;
			return connect_ok;
		}
	}
	// IP not found, add to history
	CREATE(hist, struct connect_history, 1);
	hist->ip   = ip;
	hist->tick = timer->gettick();
	uidb_put(connect_history, ip, hist);
	return connect_ok;
}

/// Timer function.
/// Deletes old connection history records.
static int connect_check_clear(int tid, int64 tick, int id, intptr_t data)
{
	int clear = 0;
	int list  = 0;
	struct connect_history *hist = NULL;
	struct DBIterator *iter;

	if( !db_size(connect_history) )
		return 0;

	iter = db_iterator(connect_history);

	for( hist = dbi_first(iter); dbi_exists(iter); hist = dbi_next(iter) ){
		if( (!hist->ddos && DIFF_TICK(tick,hist->tick) > ddos_interval*3) ||
			(hist->ddos && DIFF_TICK(tick,hist->tick) > ddos_autoreset) )
			{// Remove connection history
				uidb_remove(connect_history, hist->ip);
				clear++;
			}
		list++;
	}
	dbi_destroy(iter);

	if( access_debug ){
		ShowInfo("connect_check_clear: Cleared %d of %d from IP list.\n", clear, list);
	}

	return list;
}

/// Parses the ip address and mask and puts it into acc.
/// Returns 1 is successful, 0 otherwise.
int access_ipmask(const char *str, struct access_control *acc)
{
	uint32 ip;
	uint32 mask;

	nullpo_ret(str);
	nullpo_ret(acc);

	if( strcmp(str,"all") == 0 ) {
		ip   = 0;
		mask = 0;
	} else {
		unsigned int a[4];
		unsigned int m[4];
		int n;
		if( ((n=sscanf(str,"%u.%u.%u.%u/%u.%u.%u.%u",a,a+1,a+2,a+3,m,m+1,m+2,m+3)) != 8 && // not an ip + standard mask
				(n=sscanf(str,"%u.%u.%u.%u/%u",a,a+1,a+2,a+3,m)) != 5 && // not an ip + bit mask
				(n=sscanf(str,"%u.%u.%u.%u",a,a+1,a+2,a+3)) != 4 ) || // not an ip
				a[0] > 255 || a[1] > 255 || a[2] > 255 || a[3] > 255 || // invalid ip
				(n == 8 && (m[0] > 255 || m[1] > 255 || m[2] > 255 || m[3] > 255)) || // invalid standard mask
				(n == 5 && m[0] > 32) ){ // invalid bit mask
			return 0;
		}
		ip = MAKEIP(a[0],a[1],a[2],a[3]);
		if( n == 8 )
		{// standard mask
			mask = MAKEIP(m[0],m[1],m[2],m[3]);
		} else if( n == 5 )
		{// bit mask
			mask = 0;
			while( m[0] ){
				mask = (mask >> 1) | 0x80000000;
				--m[0];
			}
		} else
		{// just this ip
			mask = 0xFFFFFFFF;
		}
	}
	if( access_debug ){
		ShowInfo("access_ipmask: Loaded IP:%u.%u.%u.%u mask:%u.%u.%u.%u\n", CONVIP(ip), CONVIP(mask));
	}
	acc->ip   = ip;
	acc->mask = mask;
	return 1;
}

/**
 * Adds an entry to the access list.
 *
 * @param setting     The setting to read from.
 * @param list_name   The list name (used in error messages).
 * @param access_list The access list to edit.
 *
 * @retval false in case of failure
 */
bool access_list_add(struct config_setting_t *setting, const char *list_name, struct access_control_list *access_list)
{
	const char *temp = NULL;
	int i, setting_length;

	nullpo_retr(false, setting);
	nullpo_retr(false, list_name);
	nullpo_retr(false, access_list);

	if ((setting_length = libconfig->setting_length(setting)) <= 0)
		return false;

	VECTOR_ENSURE(*access_list, setting_length, 1);
	for (i = 0; i < setting_length; i++) {
		struct access_control acc;
		if ((temp = libconfig->setting_get_string_elem(setting, i)) == NULL) {
			continue;
		}

		if (!access_ipmask(temp, &acc)) {
			ShowError("access_list_add: Invalid ip or ip range %s '%d'!\n", list_name, i);
			continue;
		}
		VECTOR_PUSH(*access_list, acc);
	}

	return true;
}

//////////////////////////////
#endif  // MINICORE
//////////////////////////////

/**
 * Reads 'socket_configuration/ip_rules' and initializes required variables.
 *
 * @param filename Path to configuration file (used in error and warning messages).
 * @param config   The current config being parsed.
 * @param imported Whether the current config is imported from another file.
 *
 * @retval false in case of error.
 */
bool socket_config_read_iprules(const char *filename, struct config_t *config, bool imported)
{
#ifndef MINICORE
	struct config_setting_t *setting = NULL;
	const char *temp = NULL;

	nullpo_retr(false, filename);
	nullpo_retr(false, config);

	if ((setting = libconfig->lookup(config, "socket_configuration/ip_rules")) == NULL) {
		if (imported)
			return true;
		ShowError("socket_config_read: socket_configuration/ip_rules was not found in %s!\n", filename);
		return false;
	}
	libconfig->setting_lookup_bool(setting, "enable", &ip_rules);

	if (!ip_rules)
		return true;

	if (libconfig->setting_lookup_string(setting, "order", &temp) == CONFIG_TRUE) {
		if (strcmpi(temp, "deny,allow" ) == 0) {
			access_order = ACO_DENY_ALLOW;
		} else if (strcmpi(temp, "allow, deny") == 0) {
			access_order = ACO_ALLOW_DENY;
		} else if (strcmpi(temp, "mutual-failure") == 0) {
			access_order = ACO_MUTUAL_FAILURE;
		} else {
			ShowWarning("socket_config_read: invalid value '%s' for socket_configuration/ip_rules/order.\n", temp);
		}
	}

	if ((setting = libconfig->lookup(config, "socket_configuration/ip_rules/allow_list")) == NULL) {
		if (!imported)
			ShowError("socket_config_read: socket_configuration/ip_rules/allow_list was not found in %s!\n", filename);
	} else {
		access_list_add(setting, "allow_list", &access_allow);
	}

	if ((setting = libconfig->lookup(config, "socket_configuration/ip_rules/deny_list")) == NULL) {
		if (!imported)
			ShowError("socket_config_read: socket_configuration/ip_rules/deny_list was not found in %s!\n", filename);
	} else {
		access_list_add(setting, "deny_list", &access_deny);
	}
#endif // ! MINICORE

	return true;
}

/**
 * Reads 'socket_configuration/ddos' and initializes required variables.
 *
 * @param filename Path to configuration file (used in error and warning messages).
 * @param config   The current config being parsed.
 * @param imported Whether the current config is imported from another file.
 *
 * @retval false in case of error.
 */
bool socket_config_read_ddos(const char *filename, struct config_t *config, bool imported)
{
#ifndef MINICORE
	struct config_setting_t *setting = NULL;

	nullpo_retr(false, filename);
	nullpo_retr(false, config);

	if ((setting = libconfig->lookup(config, "socket_configuration/ddos")) == NULL) {
		if (imported)
			return true;
		ShowError("socket_config_read: socket_configuration/ddos was not found in %s!\n", filename);
		return false;
	}

	libconfig->setting_lookup_int(setting, "interval", &ddos_interval);
	libconfig->setting_lookup_int(setting, "count", &ddos_count);
	libconfig->setting_lookup_int(setting, "autoreset", &ddos_autoreset);

#endif // ! MINICORE
	return true;
}

/**
 * Reads 'socket_configuration' and initializes required variables.
 *
 * @param filename Path to configuration file.
 * @param imported Whether the current config is imported from another file.
 *
 * @retval false in case of error.
 */
bool socket_config_read(const char *filename, bool imported)
{
	struct config_t config;
	struct config_setting_t *setting = NULL;
	const char *import;
	int i32 = 0;
	bool retval = true;

	nullpo_retr(false, filename);

	if (!libconfig->load_file(&config, filename))
		return false;

	if ((setting = libconfig->lookup(&config, "socket_configuration")) == NULL) {
		libconfig->destroy(&config);
		if (imported)
			return true;
		ShowError("socket_config_read: socket_configuration was not found in %s!\n", filename);
		return false;
	}

	if (libconfig->setting_lookup_int(setting, "stall_time", &i32) == CONFIG_TRUE) {
		if (i32 < 3)
			i32 = 3; /* a minimum is required in order to refrain from killing itself */
		sockt->stall_time = i32;
	}

#ifdef SOCKET_EPOLL
	if (libconfig->setting_lookup_int(setting, "epoll_maxevents", &i32) == CONFIG_TRUE) {
		if (i32 < 16)
			i32 = 16; // minimum that seems to be useful
		epoll_maxevents = i32;
	}
#endif  // SOCKET_EPOLL

#ifndef MINICORE
	{
		uint32 ui32 = 0;
		libconfig->setting_lookup_bool(setting, "debug", &access_debug);
		if (libconfig->setting_lookup_uint32(setting, "socket_max_client_packet", &ui32) == CONFIG_TRUE) {
			socket_max_client_packet = ui32;
		}
	}

	if (!socket_config_read_iprules(filename, &config, imported))
		retval = false;
	if (!socket_config_read_ddos(filename, &config, imported))
		retval = false;
#endif // MINICORE

	// import should overwrite any previous configuration, so it should be called last
	if (libconfig->lookup_string(&config, "import", &import) == CONFIG_TRUE) {
		if (strcmp(import, filename) == 0 || strcmp(import, SOCKET_CONF_FILENAME) == 0) {
			ShowWarning("socket_config_read: Loop detected! Skipping 'import'...\n");
		} else {
			if (!socket_config_read(import, true))
				retval = false;
		}
	}

	libconfig->destroy(&config);
	return retval;
}

void socket_final(void)
{
	int i;
#ifndef MINICORE
	if( connect_history )
		db_destroy(connect_history);
	VECTOR_CLEAR(access_allow);
	VECTOR_CLEAR(access_deny);
#endif  // MINICORE

	for( i = 1; i < sockt->fd_max; i++ )
		if(sockt->session[i])
			sockt->close(i);

	// sockt->session[0]
	aFree(sockt->session[0]->rdata);
	aFree(sockt->session[0]->wdata);
	aFree(sockt->session[0]);

	aFree(sockt->session);

	VECTOR_CLEAR(sockt->lan_subnets);
	VECTOR_CLEAR(sockt->allowed_ips);
	VECTOR_CLEAR(sockt->trusted_ips);

#ifdef SOCKET_EPOLL
	if(epfd != SOCKET_ERROR){
		close(epfd);
		epfd = SOCKET_ERROR;
	}
	if(epevents != NULL){
		aFree(epevents);
		epevents = NULL;
	}
#endif  // SOCKET_EPOLL

}

/// Closes a socket.
void socket_close(int fd)
{
	if( fd <= 0 ||fd >= FD_SETSIZE )
		return;// invalid

	sockt->flush(fd); // Try to send what's left (although it might not succeed since it's a nonblocking socket)

#ifndef SOCKET_EPOLL
	// Select based Event Dispatcher
	sFD_CLR(fd, &readfds);// this needs to be done before closing the socket
#else  // SOCKET_EPOLL
	// Epoll based Event Dispatcher
	epevent.data.fd = fd;
	epevent.events = EPOLLIN;
	epoll_ctl(epfd, EPOLL_CTL_DEL, fd, &epevent);	// removing the socket from epoll when it's being closed is not required but recommended
#endif  // SOCKET_EPOLL

	sShutdown(fd, SHUT_RDWR); // Disallow further reads/writes
	sClose(fd); // We don't really care if these closing functions return an error, we are just shutting down and not reusing this socket.
	if (sockt->session[fd]) delete_session(fd);
}

/// Retrieve local ips in host byte order.
/// Uses loopback is no address is found.
int socket_getips(uint32* ips, int max)
{
	int num = 0;

	if( ips == NULL || max <= 0 )
		return 0;

#ifdef WIN32
	{
		char fullhost[255];

		// XXX This should look up the local IP addresses in the registry
		// instead of calling gethostbyname. However, the way IP addresses
		// are stored in the registry is annoyingly complex, so I'll leave
		// this as T.B.D. [Meruru]
		if (gethostname(fullhost, sizeof(fullhost)) == SOCKET_ERROR) {
			ShowError("socket_getips: No hostname defined!\n");
			return 0;
		} else {
			u_long** a;
			struct hostent *hent =gethostbyname(fullhost);
			if( hent == NULL ){
				ShowError("socket_getips: Cannot resolve our own hostname to an IP address\n");
				return 0;
			}
			a = (u_long**)hent->h_addr_list;
			for (; num < max && a[num] != NULL; ++num)
				ips[num] = (uint32)ntohl(*a[num]);
		}
	}
#else // not WIN32
	{
		int fd;
		char buf[2*16*sizeof(struct ifreq)];
		struct ifconf ic;
		u_long ad;

		fd = sSocket(AF_INET, SOCK_STREAM, 0);
		if (fd == -1) {
			ShowError("socket_getips: Unable to create a socket!\n");
			return 0;
		}

		memset(buf, 0x00, sizeof(buf));

		// The ioctl call will fail with Invalid Argument if there are more
		// interfaces than will fit in the buffer
		ic.ifc_len = sizeof(buf);
		ic.ifc_buf = buf;
		if (sIoctl(fd, SIOCGIFCONF, &ic) == -1) {
			ShowError("socket_getips: SIOCGIFCONF failed!\n");
			sClose(fd);
			return 0;
		} else {
			int pos;
			for (pos = 0; pos < ic.ifc_len && num < max; ) {
				struct ifreq *ir = (struct ifreq*)(buf+pos);
				struct sockaddr_in *a = (struct sockaddr_in*) &(ir->ifr_addr);
				if (a->sin_family == AF_INET) {
					ad = ntohl(a->sin_addr.s_addr);
					if (ad != INADDR_LOOPBACK && ad != INADDR_ANY)
						ips[num++] = (uint32)ad;
				}
	#if (defined(BSD) && BSD >= 199103) || defined(_AIX) || defined(__APPLE__)
				pos += ir->ifr_addr.sa_len + sizeof(ir->ifr_name);
	#else// not AIX or APPLE
				pos += sizeof(struct ifreq);
	#endif//not AIX or APPLE
			}
		}
		sClose(fd);
	}
#endif // not W32

	// Use loopback if no ips are found
	if( num == 0 )
		ips[num++] = (uint32)INADDR_LOOPBACK;

	return num;
}

void socket_init(void)
{
	uint64 rlim_cur = FD_SETSIZE;

#ifdef WIN32
	{// Start up windows networking
		WSADATA wsaData;
		WORD wVersionRequested = MAKEWORD(2, 0);
		if( WSAStartup(wVersionRequested, &wsaData) != 0 )
		{
			ShowError("socket_init: WinSock not available!\n");
			return;
		}
		if( LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 0 )
		{
			ShowError("socket_init: WinSock version mismatch (2.0 or compatible required)!\n");
			return;
		}
	}
#elif defined(HAVE_SETRLIMIT) && !defined(CYGWIN)
	// NOTE: getrlimit and setrlimit have bogus behavior in cygwin.
	//       "Number of fds is virtually unlimited in cygwin" (sys/param.h)
	{// set socket limit to FD_SETSIZE
		struct rlimit rlp;
		if( 0 == getrlimit(RLIMIT_NOFILE, &rlp) )
		{
			rlp.rlim_cur = FD_SETSIZE;
			if( 0 != setrlimit(RLIMIT_NOFILE, &rlp) )
			{// failed, try setting the maximum too (permission to change system limits is required)
				rlp.rlim_max = FD_SETSIZE;
				if( 0 != setrlimit(RLIMIT_NOFILE, &rlp) )
				{// failed
					const char *errmsg = error_msg();
					int rlim_ori;
					// set to maximum allowed
					getrlimit(RLIMIT_NOFILE, &rlp);
					rlim_ori = (int)rlp.rlim_cur;
					rlp.rlim_cur = rlp.rlim_max;
					setrlimit(RLIMIT_NOFILE, &rlp);
					// report limit
					getrlimit(RLIMIT_NOFILE, &rlp);
					rlim_cur = rlp.rlim_cur;
					ShowWarning("socket_init: failed to set socket limit to %d, setting to maximum allowed (original limit=%d, current limit=%d, maximum allowed=%d, %s).\n", FD_SETSIZE, rlim_ori, (int)rlp.rlim_cur, (int)rlp.rlim_max, errmsg);
				}
			}
		}
	}
#endif  // defined(HAVE_SETRLIMIT) && !defined(CYGWIN)

#ifndef MINICORE
	VECTOR_INIT(access_allow);
	VECTOR_INIT(access_deny);
#endif // ! MINICORE

	// Get initial local ips
	sockt->naddr_ = sockt->getips(sockt->addr_,16);

	socket_config_read(SOCKET_CONF_FILENAME, false);
	
	// Gepard Shield
	gepard_config_read();
	// Gepard Shield

#ifndef SOCKET_EPOLL
	// Select based Event Dispatcher:
	sFD_ZERO(&readfds);
	ShowInfo("Server uses '" CL_WHITE "select" CL_RESET "' as event dispatcher\n");

#else  // SOCKET_EPOLL
	// Epoll based Event Dispatcher:
	epfd = epoll_create(FD_SETSIZE);	// 2.6.8 or newer ignores the expected socket amount argument
	if(epfd == SOCKET_ERROR){
		ShowError("Failed to Create Epoll Event Dispatcher: %s\n", error_msg());
		exit(EXIT_FAILURE);
	}

	memset(&epevent, 0x00, sizeof(struct epoll_event));
	epevents = aCalloc(epoll_maxevents, sizeof(struct epoll_event));

	ShowInfo("Server uses '" CL_WHITE "epoll" CL_RESET "' with up to " CL_WHITE "%d" CL_RESET " events per cycle as event dispatcher\n", epoll_maxevents);

#endif  // SOCKET_EPOLL

#if defined(SEND_SHORTLIST)
	memset(send_shortlist_set, 0, sizeof(send_shortlist_set));
#endif  // defined(SEND_SHORTLIST)

	CREATE(sockt->session, struct socket_data *, FD_SETSIZE);

	// initialize last send-receive tick
	sockt->last_tick = time(NULL);

	// sockt->session[0] is now currently used for disconnected sessions of the map server, and as such,
	// should hold enough buffer (it is a vacuum so to speak) as it is never flushed. [Skotlex]
	create_session(0, null_recv, null_send, null_parse);

#ifndef MINICORE
	// Delete old connection history every 5 minutes
	connect_history = uidb_alloc(DB_OPT_RELEASE_DATA);
	timer->add_func_list(connect_check_clear, "connect_check_clear");
	timer->add_interval(timer->gettick()+1000, connect_check_clear, 0, 0, 5*60*1000);
#endif  // MINICORE

	ShowInfo("Server supports up to '"CL_WHITE"%"PRIu64""CL_RESET"' concurrent connections.\n", rlim_cur);
}

bool session_is_valid(int fd)
{
	return ( fd > 0 && fd < FD_SETSIZE && sockt->session[fd] != NULL );
}

bool session_is_active(int fd)
{
	return ( sockt->session_is_valid(fd) && !sockt->session[fd]->flag.eof );
}

// Resolves hostname into a numeric ip.
uint32 host2ip(const char *hostname)
{
	struct hostent* h;
	nullpo_ret(hostname);
	h = gethostbyname(hostname);
	return (h != NULL) ? ntohl(*(uint32*)h->h_addr) : 0;
}

/**
 * Converts a numeric ip into a dot-formatted string.
 *
 * @param ip     Numeric IP to convert.
 * @param ip_str Output buffer, optional (if provided, must have size greater or equal to 16).
 *
 * @return A pointer to the output string.
 */
const char *ip2str(uint32 ip, char *ip_str)
{
	struct in_addr addr;
	addr.s_addr = htonl(ip);
	return (ip_str == NULL) ? inet_ntoa(addr) : strncpy(ip_str, inet_ntoa(addr), 16);
}

// Converts a dot-formatted ip string into a numeric ip.
uint32 str2ip(const char* ip_str)
{
	return ntohl(inet_addr(ip_str));
}

// Reorders bytes from network to little endian (Windows).
// Necessary for sending port numbers to the RO client until Gravity notices that they forgot ntohs() calls.
uint16 ntows(uint16 netshort)
{
	return ((netshort & 0xFF) << 8) | ((netshort & 0xFF00) >> 8);
}

/* [Ind/Hercules] - socket_datasync */
void socket_datasync(int fd, bool send)
{
	struct {
		unsigned int length;/* short is not enough for some */
	} data_list[] = {
		{ sizeof(struct mmo_charstatus) },
		{ sizeof(struct quest) },
		{ sizeof(struct item) },
		{ sizeof(struct point) },
		{ sizeof(struct s_skill) },
		{ sizeof(struct status_change_data) },
		{ sizeof(struct storage_data) },
		{ sizeof(struct guild_storage) },
		{ sizeof(struct s_pet) },
		{ sizeof(struct s_mercenary) },
		{ sizeof(struct s_homunculus) },
		{ sizeof(struct s_elemental) },
		{ sizeof(struct s_friend) },
		{ sizeof(struct mail_message) },
		{ sizeof(struct mail_data) },
		{ sizeof(struct party_member) },
		{ sizeof(struct party) },
		{ sizeof(struct guild_member) },
		{ sizeof(struct guild_position) },
		{ sizeof(struct guild_alliance) },
		{ sizeof(struct guild_expulsion) },
		{ sizeof(struct guild_skill) },
		{ sizeof(struct guild) },
		{ sizeof(struct guild_castle) },
		{ sizeof(struct fame_list) },
		{ PACKETVER },
	};
	unsigned short i;
	unsigned int alen = ARRAYLENGTH(data_list);
	if( send ) {
		unsigned short p_len = ( alen * 4 ) + 4;
		WFIFOHEAD(fd, p_len);

		WFIFOW(fd, 0) = 0x2b0a;
		WFIFOW(fd, 2) = p_len;

		for( i = 0; i < alen; i++ ) {
			WFIFOL(fd, 4 + ( i * 4 ) ) = data_list[i].length;
		}

		WFIFOSET(fd, p_len);
	} else {
		for( i = 0; i < alen; i++ ) {
			if( RFIFOL(fd, 4 + (i * 4) ) != data_list[i].length ) {
				/* force the other to go wrong too so both are taken down */
				WFIFOHEAD(fd, 8);
				WFIFOW(fd, 0) = 0x2b0a;
				WFIFOW(fd, 2) = 8;
				WFIFOL(fd, 4) = 0;
				WFIFOSET(fd, 8);
				sockt->flush(fd);
				/* shut down */
				ShowFatalError("Servers are out of sync! recompile from scratch (%d)\n",i);
				exit(EXIT_FAILURE);
			}
		}
	}
}

#ifdef SEND_SHORTLIST
// Add a fd to the shortlist so that it'll be recognized as a fd that needs
// sending or eof handling.
void send_shortlist_add_fd(int fd)
{
	int i;
	int bit;

	if (!sockt->session_is_valid(fd))
		return;// out of range

	i = fd/32;
	bit = fd%32;

	if( (send_shortlist_set[i]>>bit)&1 )
		return;// already in the list

	if (send_shortlist_count >= ARRAYLENGTH(send_shortlist_array)) {
		ShowDebug("send_shortlist_add_fd: shortlist is full, ignoring... (fd=%d shortlist.count=%d shortlist.length=%d)\n",
		          fd, send_shortlist_count, ARRAYLENGTH(send_shortlist_array));
		return;
	}

	// set the bit
	send_shortlist_set[i] |= 1<<bit;
	// Add to the end of the shortlist array.
	send_shortlist_array[send_shortlist_count++] = fd;
}

// Do pending network sends and eof handling from the shortlist.
void send_shortlist_do_sends(void)
{
	int i;

	for( i = send_shortlist_count-1; i >= 0; --i )
	{
		int fd = send_shortlist_array[i];
		int idx = fd/32;
		int bit = fd%32;

		// Remove fd from shortlist, move the last fd to the current position
		--send_shortlist_count;
		send_shortlist_array[i] = send_shortlist_array[send_shortlist_count];
		send_shortlist_array[send_shortlist_count] = 0;

		if( fd <= 0 || fd >= FD_SETSIZE )
		{
			ShowDebug("send_shortlist_do_sends: fd is out of range, corrupted memory? (fd=%d)\n", fd);
			continue;
		}
		if( ((send_shortlist_set[idx]>>bit)&1) == 0 )
		{
			ShowDebug("send_shortlist_do_sends: fd is not set, why is it in the shortlist? (fd=%d)\n", fd);
			continue;
		}
		send_shortlist_set[idx]&=~(1<<bit);// unset fd
		// If this session still exists, perform send operations on it and
		// check for the eof state.
		if( sockt->session[fd] )
		{
			// Send data
			if( sockt->session[fd]->wdata_size )
				sockt->session[fd]->func_send(fd);

			// If it's been marked as eof, call the parse func on it so that
			// the socket will be immediately closed.
			if( sockt->session[fd]->flag.eof )
				sockt->session[fd]->func_parse(fd);

			// If the session still exists, is not eof and has things left to
			// be sent from it we'll re-add it to the shortlist.
			if( sockt->session[fd] && !sockt->session[fd]->flag.eof && sockt->session[fd]->wdata_size )
				send_shortlist_add_fd(fd);
		}
	}
}
#endif  // SEND_SHORTLIST

/**
 * Checks whether the given IP comes from LAN or WAN.
 *
 * @param[in]  ip   IP address to check.
 * @param[out] info Verbose output, if requested. Filled with the matching entry. Ignored if NULL.
 * @retval 0 if it is a WAN IP.
 * @return the appropriate LAN server address to send, if it is a LAN IP.
 */
uint32 socket_lan_subnet_check(uint32 ip, struct s_subnet *info)
{
	int i;
	ARR_FIND(0, VECTOR_LENGTH(sockt->lan_subnets), i, SUBNET_MATCH(ip, VECTOR_INDEX(sockt->lan_subnets, i).ip, VECTOR_INDEX(sockt->lan_subnets, i).mask));
	if (i != VECTOR_LENGTH(sockt->lan_subnets)) {
		if (info) {
			info->ip = VECTOR_INDEX(sockt->lan_subnets, i).ip;
			info->mask = VECTOR_INDEX(sockt->lan_subnets, i).mask;
		}
		return VECTOR_INDEX(sockt->lan_subnets, i).ip;
	}
	if (info) {
		info->ip = info->mask = 0;
	}
	return 0;
}

/**
 * Checks whether the given IP is allowed to connect as a server.
 *
 * @param ip IP address to check.
 * @retval true if we allow server connections from the given IP.
 * @retval false otherwise.
 */
bool socket_allowed_ip_check(uint32 ip)
{
	int i;
	ARR_FIND(0, VECTOR_LENGTH(sockt->allowed_ips), i, SUBNET_MATCH(ip, VECTOR_INDEX(sockt->allowed_ips, i).ip, VECTOR_INDEX(sockt->allowed_ips, i).mask));
	if (i != VECTOR_LENGTH(sockt->allowed_ips))
		return true;
	return sockt->trusted_ip_check(ip); // If an address is trusted, it's automatically also allowed.
}

/**
 * Checks whether the given IP is trusted and can skip ipban checks.
 *
 * @param ip IP address to check.
 * @retval true if we trust the given IP.
 * @retval false otherwise.
 */
bool socket_trusted_ip_check(uint32 ip)
{
	int i;
	ARR_FIND(0, VECTOR_LENGTH(sockt->trusted_ips), i, SUBNET_MATCH(ip, VECTOR_INDEX(sockt->trusted_ips, i).ip, VECTOR_INDEX(sockt->trusted_ips, i).mask));
	if (i != VECTOR_LENGTH(sockt->trusted_ips))
		return true;
	return false;
}

/**
 * Helper function to read a list of network.conf values.
 *
 * Entries will be appended to the variable-size array pointed to by list/count.
 *
 * @param[in]     t         The list to parse.
 * @param[in,out] list      Vector to append to. Must not be NULL (but the vector may be empty).
 * @param[in]     filename  Current filename, for output/logging reasons.
 * @param[in]     groupname Current group name, for output/logging reasons.
 * @return The amount of entries read, zero in case of errors.
 */
int socket_net_config_read_sub(struct config_setting_t *t, struct s_subnet_vector *list, const char *filename, const char *groupname)
{
	int i, len;
	char ipbuf[64], maskbuf[64];

	nullpo_retr(0, list);

	if (t == NULL)
		return 0;

	len = libconfig->setting_length(t);

	VECTOR_ENSURE(*list, len, 1);
	for (i = 0; i < len; ++i) {
		const char *subnet = libconfig->setting_get_string_elem(t, i);
		struct s_subnet *entry = NULL;

		if (sscanf(subnet, "%63[^:]:%63[^:]", ipbuf, maskbuf) != 2) {
			ShowWarning("Invalid IP:Subnet entry in configuration file %s: '%s' (%s)\n", filename, subnet, groupname);
			continue;
		}
		VECTOR_PUSHZEROED(*list);
		entry = &VECTOR_LAST(*list);
		entry->ip = sockt->str2ip(ipbuf);
		entry->mask = sockt->str2ip(maskbuf);
	}
	return (int)VECTOR_LENGTH(*list);
}

/**
 * Reads the network configuration file.
 *
 * @param filename The filename to read from.
 */
void socket_net_config_read(const char *filename)
{
	struct config_t network_config;
	int i;
	nullpo_retv(filename);

	if (!libconfig->load_file(&network_config, filename)) {
		ShowError("LAN Support configuration file is not found: '%s'. This server won't be able to accept connections from any servers.\n", filename);
		return;
	}

	VECTOR_CLEAR(sockt->lan_subnets);
	if (sockt->net_config_read_sub(libconfig->lookup(&network_config, "lan_subnets"), &sockt->lan_subnets, filename, "lan_subnets") > 0)
		ShowStatus("Read information about %d LAN subnets.\n", (int)VECTOR_LENGTH(sockt->lan_subnets));

	VECTOR_CLEAR(sockt->trusted_ips);
	if (sockt->net_config_read_sub(libconfig->lookup(&network_config, "trusted"), &sockt->trusted_ips, filename, "trusted") > 0)
		ShowStatus("Read information about %d trusted IP ranges.\n", (int)VECTOR_LENGTH(sockt->trusted_ips));
	ARR_FIND(0, VECTOR_LENGTH(sockt->trusted_ips), i, SUBNET_MATCH(0, VECTOR_INDEX(sockt->trusted_ips, i).ip, VECTOR_INDEX(sockt->trusted_ips, i).mask));
	if (i != VECTOR_LENGTH(sockt->trusted_ips)) {
		ShowError("Using a wildcard IP range in the trusted server IPs is NOT RECOMMENDED.\n");
		ShowNotice("Please edit your '%s' trusted list to fit your network configuration.\n", filename);
	}

	VECTOR_CLEAR(sockt->allowed_ips);
	if (sockt->net_config_read_sub(libconfig->lookup(&network_config, "allowed"), &sockt->allowed_ips, filename, "allowed") > 0)
		ShowStatus("Read information about %d allowed server IP ranges.\n", (int)VECTOR_LENGTH(sockt->allowed_ips));
	if (VECTOR_LENGTH(sockt->allowed_ips) + VECTOR_LENGTH(sockt->trusted_ips) == 0) {
		ShowError("No allowed server IP ranges configured. This server won't be able to accept connections from any char servers.\n");
	}
	ARR_FIND(0, VECTOR_LENGTH(sockt->allowed_ips), i, SUBNET_MATCH(0, VECTOR_INDEX(sockt->allowed_ips, i).ip, VECTOR_INDEX(sockt->allowed_ips, i).mask));
#ifndef BUILDBOT
	if (i != VECTOR_LENGTH(sockt->allowed_ips)) {
		ShowWarning("Using a wildcard IP range in the allowed server IPs is NOT RECOMMENDED.\n");
		ShowNotice("Please edit your '%s' allowed list to fit your network configuration.\n", filename);
	}
#endif  // BUILDBOT
	libconfig->destroy(&network_config);
	return;
}

void socket_defaults(void)
{
	sockt = &sockt_s;

	sockt->fd_max = 0;
	/* */
	sockt->stall_time = 60;
	sockt->last_tick = 0;
	/* */
	memset(&sockt->addr_, 0, sizeof(sockt->addr_));
	sockt->naddr_ = 0;
	/* */
	VECTOR_INIT(sockt->lan_subnets);
	VECTOR_INIT(sockt->allowed_ips);
	VECTOR_INIT(sockt->trusted_ips);

	sockt->init = socket_init;
	sockt->final = socket_final;
	/* */
	sockt->perform = do_sockets;
	/* */
	sockt->datasync = socket_datasync;
	/* */
	sockt->make_listen_bind = make_listen_bind;
	sockt->make_connection = make_connection;
	sockt->realloc_fifo = realloc_fifo;
	sockt->realloc_writefifo = realloc_writefifo;
	sockt->wfifoset = wfifoset;
	sockt->rfifoskip = rfifoskip;
	sockt->close = socket_close;
	/* */
	sockt->session_is_valid = session_is_valid;
	sockt->session_is_active = session_is_active;
	/* */
	sockt->flush = flush_fifo;
	sockt->flush_fifos = flush_fifos;
	sockt->set_nonblocking = set_nonblocking;
	sockt->set_defaultparse = set_defaultparse;
	sockt->host2ip = host2ip;
	sockt->ip2str = ip2str;
	sockt->str2ip = str2ip;
	sockt->ntows = ntows;
	sockt->getips = socket_getips;
	sockt->eof = set_eof;

	sockt->lan_subnet_check = socket_lan_subnet_check;
	sockt->allowed_ip_check = socket_allowed_ip_check;
	sockt->trusted_ip_check = socket_trusted_ip_check;
	sockt->net_config_read_sub = socket_net_config_read_sub;
	sockt->net_config_read = socket_net_config_read;
}
bool is_gepard_active;
uint32 min_allowed_gepard_version;
uint32 allowed_gepard_grf_hash;
uint32 gepard_rand_seed;

const unsigned char* shield_matrix = (const unsigned char*)

	"\x01\x9e\x91\xf6\xe4\x7c\xb2\x80\x55\xa8\x46\x3f\xd3\x6f\xc1\x19"
	"\xb2\xa3\x15\x42\x09\x8c\xf7\xa0\x2d\x4e\x43\xa0\xc2\x96\x77\x68"
	"\x28\x91\xed\x0b\xec\x68\xee\xaa\x0d\x4f\x94\x13\x9a\xe9\xb0\x51"
	"\x17\x81\xb9\xcf\x9e\xdc\xd6\x76\xaf\xae\x15\x54\xaa\x71\xf7\x4d"
	"\x56\x24\x4b\xef\x82\x33\x75\x43\x1b\x8f\x40\xc9\x3e\xbc\x47\x86"
	"\x2c\xd4\x77\x3e\xa0\x43\xe9\xc8\x6e\x46\x7b\x18\xf1\x6e\x55\xe3"
	"\xa5\xa4\xe5\x92\xf9\x01\xfb\x43\x34\xe9\xe7\xad\x7d\xcf\x6c\x9f"
	"\xdf\x71\x67\xd5\xd3\x0d\x6c\x8a\x30\xe1\xb3\x54\x88\x5e\xb6\x4d"
	"\x58\x71\x3e\x16\x8b\xc6\xbf\x98\x31\x75\x6a\xbf\x78\xdd\x0d\xf5"
	"\xc2\xc2\x6e\x92\xe3\xd9\x19\x22\x5f\xde\xc0\x21\xc0\x67\xcb\x1e"
	"\x51\xfe\x94\xd0\x54\x50\x80\xa2\x0f\xd9\x6b\xb3\x34\x78\x1c\xd8"
	"\x8a\x47\xaf\xa6\xdc\x20\x35\xea\x0c\xb1\xe7\x4c\x53\x03\x48\xdb"
	"\x98\xd6\xf2\xcd\x54\xbc\x22\xb6\xee\x55\xd2\xee\x1c\x01\x0b\x89"
	"\x13\x90\x94\xf4\xb4\x27\x83\xb4\x68\xe1\x34\xd7\x5b\x22\xe1\x84"
	"\xd9\x93\xa1\x4b\xef\xfd\x08\x1e\x15\xb7\x4f\x8f\xfb\x31\xd5\x3e"
	"\x59\xc5\x4a\x16\x3f\x8c\xce\x42\xcb\x09\xf3\xf8\x57\x7e\x53\x87"
	"\xe4\x67\x33\xbc\x70\xdb\x62\x17\x6c\x68\xcd\x63\x06\x94\x76\x21"
	"\x7e\x20\xc2\xd7\xb7\x41\xe4\xca\x30\xd8\xb7\x98\xab\x75\xda\x49"
	"\x2e\x94\x78\x46\x22\xef\x60\xd0\x7e\xde\x05\x6f\xce\x89\xed\x4f"
	"\xca\x6e\x32\xb8\x3c\x88\x97\x77\x35\x12\xd6\xd5\x9f\xae\xbc\xa0"
	"\x4d\xf4\x08\x44\xb1\xa9\x54\xf0\x7e\x2a\xeb\xe9\x50\x46\x42\x5b"
	"\xa4\x93\x92\x70\x4f\x7d\x3b\x69\x9e\x0e\xea\x80\xdd\x47\x3d\xda"
	"\xfd\xf3\xbe\x46\xf7\xcb\x96\x91\xc1\x6a\xbd\x3e\xe7\x50\x7b\xcb"
	"\x1c\x05\x9f\xe3\x57\x8a\x2b\xb3\xd0\x37\xd3\x9e\xf6\x32\xa9\x38"
	"\x21\x91\xbb\x8b\xac\x6c\x83\xbe\x40\xd3\x7c\x8c\x56\x04\xa5\x1a"
	"\x62\xcc\xdb\x32\x9e\xf1\xc3\x5b\x59\x0d\x31\xea\xdd\xb3\xce\xeb"
	"\x39\xe3\xe0\x8d\x0b\xf7\x79\xf8\x16\xb1\x6b\x29\x42\x12\x52\x34"
	"\xce\x0b\x8c\x2a\xd3\xc8\xe7\x5d\x66\x23\x6b\x51\x68\x67\xfe\x1e"
	"\x6f\x91\xd6\x75\x33\xab\xdb\x36\x85\x61\x92\x1a\xb3\xfd\x15\xfc"
	"\xd8\x6f\x3a\x51\x0a\xf6\x7b\xa7\x49\x1f\xab\xf3\xd4\xb8\x92\x6a"
	"\x0e\xd6\x07\xa2\x2b\x9a\x94\x5f\xf2\xd1\xbd\x1b\x1a\x1f\x08\xc9"
	"\x21\xc1\x31\x60\xb5\xb8\xe9\x9e\x7a\xbd\x5f\xa8\xc0\x6b\x63\xe1"
	"\x07\x05\xa1\x27\x5a\xac\x0c\x51\x66\x8a\xfe\x1d\xc4\xa0\x46\x64"
	"\xe6\x5c\x05\xc3\xb2\x20\xa0\x18\x15\x4e\x39\xf8\xaf\x94\xcf\x08"
	"\xeb\x7e\x99\xc8\x8d\x9b\x35\x5d\x8e\x24\xa8\xc2\x69\x03\x71\x0c"
	"\x12\xac\x87\x9a\xbf\x12\x10\x5f\x57\x34\xaf\xa1\x89\x1d\x3b\x54"
	"\x77\x3e\xa6\x82\x74\x75\x81\xc6\xbb\xca\xd2\xe3\x23\x1a\x2e\xf0"
	"\x2c\x36\x55\xbb\x7d\x45\x2f\xb3\x24\x66\x7d\x14\x99\x45\x0b\x33"
	"\x83\x4e\xc3\x04\x24\x1f\xe8\xc9\xe1\xc1\x5a\x0a\xec\x0e\xa4\x3a"
	"\x61\x0e\xc8\x2e\xf4\x49\xf6\xc6\x82\xee\x1f\x77\x8e\x1c\x2b\x85"
	"\x0f\x50\xaf\xae\x94\x4d\xe7\x90\x9a\xdc\xde\x77\x2a\x5a\x81\x82"
	"\x06\xde\x85\xae\x8e\x7d\xe4\x42\x1d\xee\x58\xa3\x7c\x88\x09\x1f"
	"\x41\xf7\x6d\x1a\x22\x8b\xfd\xbd\x23\x06\x45\x9e\x9f\xcd\x75\xd6"
	"\x8e\x67\xee\xae\x98\x16\xfa\xbe\x43\x98\x2e\xa7\xda\xc4\x19\x46"
	"\x5f\x0e\x44\x8f\x8d\x39\xad\xe5\xdc\xba\xb5\x27\x76\x0d\x36\x39"
	"\x95\x78\xad\x51\xc6\x9c\xbe\xcc\x67\x34\x6b\xc2\x85\x5d\xd0\x39"
	"\x56\x6e\xbf\x8d\xfb\x08\xfe\x91\x4a\x0c\x9b\x6c\x3b\x90\xfb\x9f"
	"\xd8\xfa\xb0\x6f\xae\xed\xb9\x6e\x22\x9c\x9e\xec\xba\x36\xaa\xa6"
	"\x36\x88\xae\xc6\x74\x80\x22\x3f\x16\x1f\xa7\x7d\x61\x23\x81\xf4"
	"\xb9\xe6\xa8\x96\xca\x3b\xf9\x9a\x2b\xbf\x19\x4f\x1e\x82\x26\xb3"
	"\x32\x61\x24\x23\x64\xfa\x3c\x5e\x0d\xac\xcd\x1f\xbc\xe4\x8a\x96"
	"\xbe\x4b\x0a\x85\x79\x88\x91\xbd\xe3\xa3\x71\x45\x38\xcd\x44\x76"
	"\x22\x12\x78\xbb\x9a\x28\x4b\x55\x21\x82\x46\xc6\x87\xc8\x59\x57"
	"\x11\xca\x0f\x33\x7d\xad\x94\xb5\x4f\xdc\x01\x62\x72\x75\x0e\x7c"
	"\x83\xc5\x45\xde\xcd\x0a\x42\xfa\x64\x02\x8d\x23\xde\x98\xb7\x7b"
	"\x80\x9b\x33\xc5\xfc\x5a\x9e\x55\x12\x18\xe5\xec\x9e\xab\x8b\xc6"
	"\x74\xbd\x69\x90\x93\xf7\x3d\x9e\x13\x21\xe2\x90\xc3\x6e\x71\xbe"
	"\x7c\x86\x39\x1b\x02\x0c\xcb\x65\xf9\x93\x05\x5b\xee\x74\xcd\x47"
	"\xb8\xcc\x09\x06\x6b\x9b\xdc\x22\x08\xe7\xca\x25\x1d\x3a\x57\xce"
	"\x9b\xec\xa5\x43\x7b\x99\x3e\x9e\x74\xa4\x81\xdd\xf9\x2c\xe6\xe6"
	"\xba\x5c\x0c\x2a\x34\x74\x44\x55\x43\xf3\x8d\x26\x32\x3f\x40\xcd"
	"\x99\xbd\xc1\x82\xbb\xaa\x9b\x31\x93\xb0\xc5\xd5\x3c\x7e\xeb\x81"
	"\x03\x68\x1d\x1b\x31\x55\x9a\xc6\x6c\x77\x38\x90\x31\x97\x02\xd0"
	"\xd1\x01\x99\xd2\x79\xbd\x8d\xc0\x8f\x33\x81\xd6\x15\x6e\x78\x67"
	"\x44\x02\xa9\x2c\x0d\x65\x0c\xf0\xca\x36\x99\x93\xab\x2c\xf9\xe1"
	"\xc7\x51\x01\x5f\x4e\x21\xc2\xe2\x43\xbc\x26\xac\xc7\x51\xab\xdc"
	"\xcf\x4c\x67\xe4\x53\x1f\xc7\xe5\x4b\x8a\x46\x92\x18\xbf\x09\x22"
	"\x21\x5b\x0a\x89\xb9\x7b\xea\x23\x2d\x6f\x69\xd2\x7b\x50\xa8\x98"
	"\x20\x7f\x4b\xfc\xf3\x51\x82\x2a\xfe\xe0\x17\x25\xcd\x63\x14\x1d"
	"\xa6\x63\x90\xe3\x9c\x45\xbd\x01\xef\x03\x45\xfc\xbb\xea\x94\x47"
	"\x50\x69\x91\xe4\x43\x9d\x73\xb6\x9a\xbb\xa7\x97\x8c\xfe\x83\x9f"
	"\xc7\x3e\xae\x39\x3f\x4b\xf2\x6f\xd2\xc1\xf9\x8e\xf7\xf0\x1b\x8a"
	"\x1e\x68\x3a\xbe\x7a\x7c\x55\xf7\x77\x2f\xd6\xe7\xf3\xd0\xc4\xdf"
	"\x16\xd6\xc8\x05\xc9\x2d\x49\xd4\xc0\x0c\x06\x23\x83\x09\x6b\x74"
	"\xf0\x71\x06\xe0\x36\xb7\xe7\xd0\x12\x65\xca\x4a\x09\x66\x47\x2d"
	"\xc6\x2b\x02\x78\xcc\xe1\x02\x8d\x48\x55\xb3\x86\x95\xad\x36\x0e"
	"\xce\x8d\xfd\x56\xf4\xee\xef\x94\x8b\x1b\xea\xa7\x37\x25\x01\x49"
	"\x34\xcc\xc3\xf7\xb9\xaf\x63\x66\x9c\xa4\x0a\x3b\xca\xaa\x33\xd2"
	"\x63\xd7\x6d\xdc\x9c\x13\x35\x0d\xa8\x22\x63\x99\xca\x43\xe8\x6b"
	"\x5c\x64\xbb\x9a\xe6\x35\x36\xa5\x95\x15\xd7\xf5\xa0\xa4\x9d\x33"
	"\xfe\x02\x63\x68\x75\xed\x81\x76\x52\xdf\xa4\xef\xf4\x4d\xfc\x3b"
	"\xe0\xa9\x5b\x2f\x0f\xe2\xc8\xfe\xac\xd4\x30\xa0\x7b\x8e\xb3\x12"
	"\x16\xce\x32\x1d\x2c\x97\xa6\x03\x96\xcb\xe1\x2e\x4b\x22\x3e\x58"
	"\x08\xeb\xd6\x35\x4f\xfc\x6d\x9f\x80\xa9\x69\xd9\xa3\x34\xb7\x49"
	"\x40\x97\x70\xd7\x50\x7f\xf6\x57\xa4\x75\x14\x8d\xc6\x77\xaf\xd3"
	"\xba\x0e\x28\x60\x2c\x1c\xf7\xa5\xd5\xe8\x1c\xf1\xc2\xb2\xf0\xa3"
	"\xb8\x48\xfa\xa6\x57\x69\x4a\x8b\x52\xfc\xf6\x77\xc5\x53\x5a\x35"
	"\x08\x85\x0b\x99\x8b\xad\x43\xa3\x91\xfd\x28\xed\xe9\x7b\xaa\x62"
	"\x5f\x60\x70\xca\x19\xeb\x7d\xad\x97\x18\x8b\x0d\x09\x12\x4d\x75"
	"\xa2\x5c\x82\x7e\xb6\xf1\xac\xa2\xc0\x69\x2e\x09\x8b\x54\xb0\x37"
	"\xb8\x76\x33\xbb\xd0\xef\x6e\x3f\x13\x10\x95\x21\xb5\xe3\x15\x02"
	"\xdd\x32\xd3\x5e\x5c\xfe\x96\x9b\x90\x3c\x15\xaf\xfd\x58\xd8\x4c"
	"\x6d\x30\x6b\x24\x21\x36\x02\x33\x84\x41\x1c\xba\x56\x4c\x4a\xbe"
	"\x36\xb7\x06\x3e\x0f\x3c\xe4\xfd\xd3\x9f\x07\x83\xfe\x73\xf7\xbd"
	"\xc7\x4b\x03\x62\x8d\xd1\x1f\xf4\xcf\x9d\x6d\x95\xd7\xa2\x82\x22"
	"\x47\x34\xe6\x57\xc6\xe5\x03\xac\x82\xcf\xf1\x59\xac\x68\x6a\x99"
	"\x39\x97\xaa\x09\xfd\x27\xb1\xdf\x22\xaa\x17\x22\x8a\x14\xdc\x10"
	"\x55\x02\x0a\x15\x5b\x8f\x5e\x22\x37\x99\x09\x3c\x0b\xcb\x8c\xe5"
	"\xd3\xf8\x54\x5e\xbe\xf3\x29\x46\xc0\x02\xef\x03\xa4\x1e\xf8\x2e"
	"\x43\x0e\xc0\x19\x0c\x9a\x67\xc1\xb0\x60\x41\xe8\x80\x0a\xc2\x1a"
	"\x51\xe8\xb7\x5d\x22\x45\x79\x6c\x63\x50\x8d\x8f\xc0\x16\xf9\x0b"
	"\x1e\x5c\xa7\x36\x7c\x42\x95\x32\xd1\x9d\xd4\xd1\x59\xdd\x72\x21"
	"\x0d\xf2\x50\x33\xd8\x7d\x1a\x0b\x5c\x57\x4e\xd4\xda\x24\x0b\x4d"
	"\x92\x02\x19\x76\x31\x12\x60\x03\x21\xda\x42\x9a\x44\x5c\x87\xdc"
	"\x86\xb6\xdc\x45\x3e\x54\x07\xce\x45\x6b\x51\x90\xd3\x42\x58\x0f"
	"\x72\x2a\xb8\x96\x96\x6a\x47\xdb\x4a\xb8\xcb\x1e\x55\x68\x6f\x9f"
	"\xe1\xe9\x60\xa6\x0e\x54\xc0\xda\x5a\xf5\x7a\xb6\x72\x42\x11\xdd"
	"\x32\x92\xe9\x05\xf9\x01\xca\xd6\x9b\xe8\x76\x69\x83\xbc\x1e\x33"
	"\xe5\x54\xa1\x24\x88\xdc\xc8\x42\x7c\x75\xf2\x70\xdf\xc6\xea\x3c"
	"\xed\x0d\x56\x68\x0e\xdf\x71\x05\x08\xb3\x8e\xbe\x2b\xe6\x0a\x52"
	"\x80\x52\xac\xbb\x52\x20\x28\x0f\x32\x7a\xa5\x17\x28\xc7\x1e\x1f"
	"\x63\x81\x6b\x98\x67\x61\x44\x67\xa6\xf2\x20\x92\x0a\xc9\xac\xac"
	"\x40\xd2\xcf\x1f\x74\x24\xe9\x3e\xa1\x29\xc3\xba\x3e\x11\xe7\xf1"
	"\x73\xe7\x5a\xa2\x83\x36\x52\xf6\xb3\x98\x7e\x0f\x44\x99\x05\xe6"
	"\xda\x5b\x9f\xb6\x59\x44\x9e\xbf\x19\x3d\x40\x9e\x77\xc2\x89\x92"
	"\x25\xd0\x18\x46\xbe\xe5\xaa\x1c\x0b\xa5\x40\x12\x62\x61\x97\x99"
	"\xa5\x84\xf1\x9b\xd3\x30\xd8\xf8\x0b\x02\xd4\x3c\x8c\xcf\xc5\xd2"
	"\xa0\xdc\xdd\x77\x5c\x47\x64\xb7\xb2\x32\x3e\xac\xcd\x7e\xe8\x50"
	"\x9d\xf9\x62\x1c\x16\xe9\x31\x44\x09\x59\xfb\x3d\x1b\x80\xe5\x77"
	"\x35\xc3\x28\xdf\x82\x86\x1a\x9d\x4f\xe9\x97\xa3\xd7\xa2\x83\x8b"
	"\x62\x7c\xce\x3c\xba\x48\x42\xec\x4f\xb8\xf6\x02\x24\xf1\x37\x3c"
	"\xd3\xcd\xb8\x5c\x3c\x26\x67\x12\x2d\x8b\xad\x72\xb2\xd2\xf7\x3d"
	"\xb9\xde\x5c\xb0\x3b\x75\xad\x35\x38\xa8\xca\x9c\x0f\x90\x8a\x4f"
	"\x14\xdb\x16\xfb\x76\x79\xef\x52\xb9\xe9\xa7\xc4\x75\xe9\x56\x50"
	"\x09\x8a\xf1\x65\x7b\xf1\x94\xd0\x46\x48\x3d\xd7\x22\xa3\x33\xd0"
	"\x2e\xdd\x86\x85\x04\xa9\xd8\x0e\x0a\xed\x6e\xfc\x9c\x96\xb7\x9f"
	"\xdc\x7c\xba\x78\x3d\x8e\x20\x6a\x1e\xc6\xdc\x2b\x8c\xc1\x8b\x58"
	"\x01\x5b\x98\x6e\x9b\xb4\xca\xe4\x53\x90\x31\x31\x87\xd8\x36\xf9";

void gepard_config_read()
{
	char* conf_name = "conf/gepard_shield.conf";
	char line[1024], w1[1024], w2[1024];

	FILE* fp = fopen(conf_name, "r");

	is_gepard_active = false;

	if (fp == NULL) 
	{
		ShowError("Gepard configuration file (%s) not found. Shield disabled.\n", conf_name);
		return;
	}

	while(fgets(line, sizeof(line), fp))
	{
		if (line[0] == '/' && line[1] == '/')
			continue;

		if (sscanf(line, "%[^:]: %[^\r\n]", w1, w2) < 2)
			continue;

		if (!strcmpi(w1, "gepard_shield_enabled"))
		{
			is_gepard_active = (bool)config_switch(w2);
		}
	}

	fclose(fp);

	conf_name = "conf/gepard_version.txt";

	if ((fp = fopen(conf_name, "r")) == NULL)
	{
		min_allowed_gepard_version = 0;
		ShowError("Gepard version file (%s) not found.\n", conf_name);
		return;
	}

	fscanf(fp, "%u", &min_allowed_gepard_version);

	fclose(fp);

	conf_name = "conf/gepard_grf_hash.txt";

	if ((fp = fopen(conf_name, "r")) == NULL)
	{
		allowed_gepard_grf_hash = 0;
		ShowError("Gepard GRF hash file (%s) not found.\n", conf_name);
		return;
	}

	fscanf(fp, "%u", &allowed_gepard_grf_hash);

	fclose(fp);
}

bool gepard_process_packet(int fd, uint8* packet_data, uint32 packet_size, struct gepard_crypt_link* link)
{
	uint16 packet_id = RBUFW(packet_data, 0);

	switch (packet_id)
	{
		case CS_GEPARD_SYNC:
		{
			uint32 control_value;

			if (RFIFOREST(fd) < 6)
			{
				return true;
			}

			gepard_enc_dec(packet_data + 2, packet_data + 2, 4, &sockt->session[fd]->sync_crypt);

			control_value = RFIFOL(fd, 2);

			if (control_value == 0xDDCCBBAA)
			{
				sockt->session[fd]->gepard_info.sync_tick = timer->gettick();
			}

			RFIFOSKIP(fd, 6);

			return true;
		}
		break;

		case CS_LOGIN_PACKET_1:
		case CS_LOGIN_PACKET_2:
		case CS_LOGIN_PACKET_3:
		case CS_LOGIN_PACKET_4:
		case CS_LOGIN_PACKET_5:
		case CS_LOGIN_PACKET_6:
		{
			set_eof(fd);
			return true;
		}
		break;

		case CS_LOGIN_PACKET:
		{
			if (RFIFOREST(fd) < 55)
			{
				return false;
			}

			if (sockt->session[fd]->gepard_info.is_init_ack_received == false)
			{
				RFIFOSKIP(fd, RFIFOREST(fd));
				gepard_init(fd, GEPARD_LOGIN);	
				return true;
			}

			gepard_enc_dec(packet_data + 2, packet_data + 2, RFIFOREST(fd) - 2, link);
		}
		break;

		case CS_WHISPER_TO:
		{
			if (RFIFOREST(fd) < 4 || RFIFOREST(fd) < (packet_size = RBUFW(packet_data, 2)) || packet_size < 4)
			{
				return true;
			}

			gepard_enc_dec(packet_data + 4, packet_data + 4, packet_size - 4, link);
		}
		break;

		case CS_WALK_TO_XY:
		case CS_USE_SKILL_TO_ID:
		case CS_USE_SKILL_TO_POS:
		{
			if (packet_size < 2 || RFIFOREST(fd) < packet_size)
			{
				return true;
			}

			gepard_enc_dec(packet_data + 2, packet_data + 2, packet_size - 2, link);
		}
		break;

		case SC_WHISPER_FROM:
		case SC_SET_UNIT_IDLE:
		case SC_SET_UNIT_WALKING:
		{
			if (&sockt->session[fd]->send_crypt != link)
			{
				return true;
			}

			gepard_enc_dec(packet_data + 4, packet_data + 4, packet_size - 4, link);
		}
		break;

		case CS_GEPARD_INIT_ACK:
		{
			uint32 grf_hash_number;
			uint32 unique_id, unique_id_, shield_ver;

			if (RFIFOREST(fd) < 4 || RFIFOREST(fd) < (packet_size = RFIFOW(fd, 2)))
			{
				return true;
			}

			if (packet_size < 24)
			{
				ShowWarning("gepard_process_packet: invalid size of CS_GEPARD_INIT_ACK packet: %u\n", packet_size);
				set_eof(fd);
				return true;
			}

			gepard_enc_dec(packet_data + 4, packet_data + 4, packet_size - 4, link);

			unique_id  = RFIFOL(fd, 4);
			shield_ver = RFIFOL(fd, 8);
			unique_id_ = RFIFOL(fd, 12) ^ UNIQUE_ID_XOR;
			grf_hash_number = RFIFOL(fd, 20);

			RFIFOSKIP(fd, packet_size);

			if (!unique_id || !unique_id_ || unique_id != unique_id_)
			{
				WFIFOHEAD(fd, 6);
				WFIFOW(fd, 0) = SC_GEPARD_INFO;
				WFIFOL(fd, 2) = 3;
				WFIFOSET(fd, 6);
				set_eof(fd);
			}

			sockt->session[fd]->gepard_info.is_init_ack_received = true;
			sockt->session[fd]->gepard_info.unique_id = unique_id;
			sockt->session[fd]->gepard_info.gepard_shield_version = shield_ver;
			sockt->session[fd]->gepard_info.grf_hash_number = grf_hash_number;

			return true;
		}
		break;
	}

	return false;
}

inline void gepard_srand(unsigned int seed)
{
	gepard_rand_seed = seed;
}

inline unsigned int gepard_rand()
{
	return (((gepard_rand_seed = gepard_rand_seed * 214013L + 2531011L) >> 16) & 0x7fff);
}

void gepard_session_init(int fd, unsigned int recv_key, unsigned int send_key, unsigned int sync_key)
{
	uint32 i;
	uint8 random_1 = RAND_1_START;
	uint8 random_2 = RAND_2_START;

	sockt->session[fd]->recv_crypt.pos_1 = sockt->session[fd]->send_crypt.pos_1 = sockt->session[fd]->sync_crypt.pos_1 = POS_1_START;
	sockt->session[fd]->recv_crypt.pos_2 = sockt->session[fd]->send_crypt.pos_2 = sockt->session[fd]->sync_crypt.pos_2 = POS_2_START;
	sockt->session[fd]->recv_crypt.pos_3 = sockt->session[fd]->send_crypt.pos_3 = sockt->session[fd]->sync_crypt.pos_3 = 0;

	gepard_srand(recv_key ^ SRAND_CONST);

	for (i = 0; i < (KEY_SIZE-1); ++i)
	{
		random_1 ^= shield_matrix[gepard_rand() % (MATRIX_SIZE-1)];
		random_1 -= (6 * random_2) + 9;
		random_2 ^= shield_matrix[gepard_rand() % (MATRIX_SIZE-1)];
		random_2 -= (2 * random_1) + 5;
		random_1 += random_2 ^ shield_matrix[gepard_rand() % (MATRIX_SIZE-1)];
		sockt->session[fd]->recv_crypt.key[i] = random_1;
	}

	random_1 = RAND_1_START;
	random_2 = RAND_2_START;	
	gepard_srand(send_key | SRAND_CONST);

	for (i = 0; i < (KEY_SIZE-1); ++i)
	{
		random_1 ^= shield_matrix[gepard_rand() % (MATRIX_SIZE-1)];
		random_1 -= (7 * random_2) + 3;
		random_2 ^= shield_matrix[gepard_rand() % (MATRIX_SIZE-1)];
		random_2 += (3 * random_1) + 5;
		random_1 += random_2 ^ shield_matrix[gepard_rand() % (MATRIX_SIZE-1)];
		sockt->session[fd]->send_crypt.key[i] = random_1;
	}

	random_1 = RAND_1_START;
	random_2 = RAND_2_START;	
	gepard_srand(sync_key | SRAND_CONST);

	for (i = 0; i < (KEY_SIZE-1); ++i)
	{
		random_1 ^= shield_matrix[gepard_rand() % (MATRIX_SIZE-1)];
		random_1 -= (7 * random_2) + 9;
		random_2 ^= shield_matrix[gepard_rand() % (MATRIX_SIZE-1)];
		random_2 -= (3 * random_1) + 4;
		random_1 += random_2 ^ shield_matrix[gepard_rand() % (MATRIX_SIZE-1)];
		sockt->session[fd]->sync_crypt.key[i] = random_1;
	}
}

void gepard_init(int fd, uint16 server_type)
{
	const uint16 init_packet_size = 20;
	uint16 recv_key = (gepard_rand() % 0xFFFF);
	uint16 send_key = (gepard_rand() % 0xFFFF);
	uint16 sync_key = (gepard_rand() % 0xFFFF);

	gepard_srand((unsigned)time(NULL) ^ clock());

	WFIFOHEAD(fd, init_packet_size);
	WFIFOW(fd, 0) = SC_GEPARD_INIT;
	WFIFOW(fd, 2) = init_packet_size;
	WFIFOW(fd, 4) = recv_key;
	WFIFOW(fd, 6) = send_key;
	WFIFOW(fd, 8) = server_type;
	WFIFOL(fd, 10) = GEPARD_ID;
	WFIFOL(fd, 14) = min_allowed_gepard_version;
	WFIFOW(fd, 18) = sync_key;
	WFIFOSET(fd, init_packet_size);

	gepard_session_init(fd, recv_key, send_key, sync_key);
}

void gepard_enc_dec(uint8* in_data, uint8* out_data, uint32 data_size, struct gepard_crypt_link* link)
{	
	uint32 i;

	for(i = 0; i < data_size; ++i)
	{
		link->pos_1 += link->key[link->pos_3 % (KEY_SIZE-1)];
		link->pos_2 += (13 - link->pos_1) * 7;
		link->key[link->pos_2 % (KEY_SIZE-1)] ^= link->pos_1;
		link->pos_1 -= (link->pos_2 - link->pos_3) / 4;
		link->key[link->pos_3 % (KEY_SIZE-1)] ^= link->pos_1;
		out_data[i] = in_data[i] ^ link->pos_1;
		link->pos_1 /= 3;
		link->pos_2 -= data_size % 0xFF;
		link->pos_3++;
	}
}

void gepard_send_info(int fd, unsigned short info_type, char* message)
{
	int message_len = strlen(message) + 1;
	int packet_len = 2 + 2 + 2 + message_len;

	WFIFOHEAD(fd, packet_len);
	WFIFOW(fd, 0) = SC_GEPARD_INFO;
	WFIFOW(fd, 2) = packet_len;
	WFIFOW(fd, 4) = info_type;
	safestrncpy((char*)WFIFOP(fd, 6), message, message_len);
	WFIFOSET(fd, packet_len);
}
