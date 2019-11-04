/*
Cuckoo Sandbox - Automated Malware Analysis
Copyright (C) 2010-2016 Cuckoo Sandbox Developers, Optiv, Inc. (brad.spengler@optiv.com), Brad Spengler

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include "ntapi.h"
#include <mswsock.h>
#include "hooking.h"
#include "log.h"
#include "config.h"
#include "misc.h"

extern BOOL DumpRegion(PVOID Address);
extern void DoOutputDebugString(_In_ LPCTSTR lpOutputString, ...);

static PVOID alloc_combined_wsabuf(LPWSABUF buf, DWORD count, DWORD *outlen)
{
	DWORD i;
	DWORD size = 0;
	PUCHAR retbuf;
	for (i = 0; i < count; i++) {
		size += buf->len;
	}

	retbuf = malloc(size);
	if (retbuf == NULL) {
		*outlen = 0;
		return retbuf;
	}

	size = 0;
	for (i = 0; i < count; i++) {
		memcpy(&retbuf[size], buf->buf, buf->len);
		size += buf->len;
	}
	*outlen = size;
	return retbuf;
}

static BOOLEAN get_ip_port(const struct sockaddr *addr,
    char *ip, int *port)
{
	lasterror_t lasterror;
	BOOLEAN ret = TRUE;

	if (addr == NULL)
		return FALSE;

	get_lasterrors(&lasterror);

	__try {
		// TODO IPv6 support.
		if (addr->sa_family == AF_INET) {
			const struct sockaddr_in *addr4 = (const struct sockaddr_in *) addr;
			addr_to_string(addr4->sin_addr, ip);
			*port = our_htons(addr4->sin_port);
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		ret = FALSE;
	}
	set_lasterrors(&lasterror);
	return ret;
}

HOOKDEF(int, WINAPI, WSAStartup,
    _In_   WORD wVersionRequested,
    _Out_  LPWSADATA lpWSAData
) {
    int ret = Old_WSAStartup(wVersionRequested, lpWSAData);
    LOQ_zero("network", "h", "VersionRequested", wVersionRequested);
    return ret;
}

HOOKDEF(struct hostent *, WSAAPI, gethostbyname,
    __in  const char *name
) {
    struct hostent *ret = Old_gethostbyname(name);

	if (g_config.url_of_interest && g_config.suspend_logging)
		g_config.suspend_logging = FALSE;

    LOQ_nonnull("network", "s", "Name", name);
    return ret;
}

HOOKDEF(SOCKET, WSAAPI, socket,
    __in  int af,
    __in  int type,
    __in  int protocol
) {
    SOCKET ret = Old_socket(af, type, protocol);
    LOQ_sock("network", "iiii", "af", af, "type", type, "protocol", protocol, "socket", ret);
    return ret;
}

HOOKDEF(int, WSAAPI, connect,
    __in  SOCKET s,
    __in  const struct sockaddr *name,
    __in  int namelen
) {
    int ret = Old_connect(s, name, namelen);
    char ip[16]; int port = 0;
    get_ip_port(name, ip, &port);
    LOQ_sockerr("network", "isi", "socket", s, "ip", ip, "port", port);
    if (g_config.dump_config_region) {
        if (DumpRegion((PVOID)name))
            DoOutputDebugString("connect hook: Successfully dumped region at 0x%p around %s.\n", name, ip);
        else
            DoOutputDebugString("connect hook: Failed to dump region at 0x%p around %s.\n", name, ip);
    }
    return ret;
}

HOOKDEF(int, WSAAPI, send,
    __in  SOCKET s,
    __in  const char *buf,
    __in  int len,
    __in  int flags
) {
    int ret = Old_send(s, buf, len, flags);
    LOQ_sockerr("network", "ib", "socket", s, "buffer", ret < 1 ? len : ret, buf);
    return ret;
}

HOOKDEF(int, WSAAPI, sendto,
    __in  SOCKET s,
    __in  const char *buf,
    __in  int len,
    __in  int flags,
    __in  const struct sockaddr *to,
    __in  int tolen
) {
    int ret = Old_sendto(s, buf, len, flags, to, tolen);
	char ip[16] = { 0 };
	int port = 0;
    get_ip_port(to, ip, &port);
    LOQ_sockerr("network", "ibsi", "socket", s, "buffer", ret < 1 ? len : ret, buf,
        "ip", ip, "port", port);
    return ret;
}

HOOKDEF(int, WSAAPI, recv,
    __in   SOCKET s,
    __out  char *buf,
    __in   int len,
    __in   int flags
) {
    int ret = Old_recv(s, buf, len, flags);
    LOQ_sockerr("network", "ib", "socket", s, "buffer", ret < 1 ? 0 : ret, buf);
    return ret;
}

HOOKDEF(int, WSAAPI, recvfrom,
    __in         SOCKET s,
    __out        char *buf,
    __in         int len,
    __in         int flags,
    __out        struct sockaddr *from,
    __inout_opt  int *fromlen
) {
    int ret = Old_recvfrom(s, buf, len, flags, from, fromlen);
	char ip[16] = { 0 };
	int port = 0;
    if(ret > 0) {
        get_ip_port(from, ip, &port);
    }
    LOQ_sockerr("network", "ibsi", "socket", s, "buffer", ret < 1 ? 0 : ret, buf,
        "ip", ip, "port", port);
    return ret;
}

typedef int (WSAAPI * __getpeername)(
	__in SOCKET s,
	__out_bcount_part(*namelen, *namelen) struct sockaddr FAR * name,
	__inout int FAR * namelen
	);
static __getpeername _getpeername;

int WSAAPI our_getpeername(__in SOCKET s,
	__out_bcount_part(*namelen, *namelen) struct sockaddr FAR * name,
	__inout int FAR * namelen
) {
	lasterror_t lasterror;
	int ret = 1;

	get_lasterrors(&lasterror);

	if (s != INVALID_SOCKET) {
		if (!_getpeername) {
			_getpeername = (__getpeername)GetProcAddress(LoadLibraryA("ws2_32"), "getpeername");
		}
		ret = _getpeername(s, name, namelen);
	}
	set_lasterrors(&lasterror);
	return ret;
}

HOOKDEF(SOCKET, WSAAPI, accept,
    __in     SOCKET s,
    __out    struct sockaddr *addr,
    __inout  int *addrlen
) {
    SOCKET ret = Old_accept(s, addr, addrlen);
	char ip_s[16] = { 0 };
	char ip_c[16] = { 0 };
	int port_s = 0, port_c = 0;
    struct sockaddr addr_c; int addr_c_len = sizeof(addr_c);

    get_ip_port(addr, ip_s, &port_s);
    if(our_getpeername(ret, &addr_c, &addr_c_len) == 0) {
        get_ip_port(&addr_c, ip_c, &port_c);
    }

    LOQ_sockerr("network", "iisisi", "socket", s, "ClientSocket", ret,
        "ip_accept", ip_s, "port_accept", port_s,
        "ip_client", ip_c, "port_client", port_c);
    return ret;
}

HOOKDEF(int, WSAAPI, bind,
    __in  SOCKET s,
    __in  const struct sockaddr *name,
    __in  int namelen
) {
    int ret = Old_bind(s, name, namelen);
	char ip[16] = { 0 };
	int port = 0;
    get_ip_port(name, ip, &port);

    LOQ_sockerr("network", "isi", "socket", s, "ip", ip, "port", port);
    return ret;
}

HOOKDEF(int, WSAAPI, listen,
    __in  SOCKET s,
    __in  int backlog
) {
    int ret = Old_listen(s, backlog);
    LOQ_sockerr("network", "i", "socket", s);
    return ret;
}

HOOKDEF(int, WSAAPI, select,
    __in     SOCKET s,
    __inout  fd_set *readfds,
    __inout  fd_set *writefds,
    __inout  fd_set *exceptfds,
    __in     const struct timeval *timeout
) {
    int ret = Old_select(s, readfds, writefds, exceptfds, timeout);
    LOQ_sockerr("network", "i", "socket", s);
    return ret;
}

HOOKDEF(int, WSAAPI, setsockopt,
    __in  SOCKET s,
    __in  int level,
    __in  int optname,
    __in  const char *optval,
    __in  int optlen
) {
    int ret = Old_setsockopt(s, level, optname, optval, optlen);
    LOQ_sockerr("network", "ippb", "socket", s, "level", level, "optname", optname,
        "optval", optlen, optval);
    return ret;
}

HOOKDEF(int, WSAAPI, ioctlsocket,
    __in     SOCKET s,
    __in     long cmd,
    __inout  u_long *argp
) {
    int ret = Old_ioctlsocket(s, cmd, argp);
    LOQ_sockerr("network", "ip", "socket", s, "command", cmd);
    return ret;
}

HOOKDEF(int, WSAAPI, closesocket,
    __in  SOCKET s
) {
    int ret = Old_closesocket(s);
    LOQ_sockerr("network", "i", "socket", s);
    return ret;
}

HOOKDEF(int, WSAAPI, shutdown,
    __in  SOCKET s,
    __in  int how
) {
    int ret = Old_shutdown(s, how);
    LOQ_sockerr("network", "ii", "socket", s, "how", how);
    return ret;
}

HOOKDEF(SOCKET, WSAAPI, WSAAccept,
    __in    SOCKET s,
    __out   struct sockaddr *addr,
    __inout LPINT addrlen,
    __in    LPCONDITIONPROC lpfnCondition,
    __in    DWORD_PTR dwCallbackData
) {
    SOCKET ret = Old_WSAAccept(s, addr, addrlen, lpfnCondition,
        dwCallbackData);
	char ip_s[16] = {0};
	char ip_c[16] = {0};
	int port_s = 0, port_c = 0;
    struct sockaddr addr_c; int addr_c_len = sizeof(addr_c);

    get_ip_port(addr, ip_s, &port_s);
    if(our_getpeername(ret, &addr_c, &addr_c_len) == 0) {
        get_ip_port(&addr_c, ip_c, &port_c);
    }

    LOQ_sockerr("network", "iisisi", "socket", s, "ClientSocket", ret,
        "ip_accept", ip_s, "port_accept", port_s,
        "ip_client", ip_c, "port_client", port_c);
    return ret;
}

HOOKDEF(int, WSAAPI, WSARecv,
    __in     SOCKET s,
    __inout  LPWSABUF lpBuffers,
    __in     DWORD dwBufferCount,
    __out    LPDWORD lpNumberOfBytesRecvd,
    __inout  LPDWORD lpFlags,
    __in     LPWSAOVERLAPPED lpOverlapped,
    __in     LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
) {
    int ret = Old_WSARecv(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd,
        lpFlags, lpOverlapped, lpCompletionRoutine);
	if (lpOverlapped == NULL && lpCompletionRoutine == NULL) {
		DWORD outlen;
		PVOID buf = alloc_combined_wsabuf(lpBuffers, dwBufferCount, &outlen);
		LOQ_sockerr("network", "iBI", "socket", s, "Buffer", lpNumberOfBytesRecvd, buf, "NumberOfBytesReceived", lpNumberOfBytesRecvd);
		if (buf)
			free(buf);
	}
	else {
		// TODO: handle completion routine case
		LOQ_sockerr("network", "i", "socket", s);
	}
    return ret;
}

HOOKDEF(int, WSAAPI, WSARecvFrom,
    __in     SOCKET s,
    __inout  LPWSABUF lpBuffers,
    __in     DWORD dwBufferCount,
    __out    LPDWORD lpNumberOfBytesRecvd,
    __inout  LPDWORD lpFlags,
    __out    struct sockaddr *lpFrom,
    __inout  LPINT lpFromlen,
    __in     LPWSAOVERLAPPED lpOverlapped,
    __in     LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
) {
    int ret = Old_WSARecvFrom(s, lpBuffers, dwBufferCount,
        lpNumberOfBytesRecvd, lpFlags, lpFrom, lpFromlen, lpOverlapped,
        lpCompletionRoutine);
	char ip[16] = { 0 };
	int port = 0;
    get_ip_port(lpFrom, ip, &port);
	if (lpOverlapped == NULL && lpCompletionRoutine == NULL) {
		DWORD outlen;
		PVOID buf = alloc_combined_wsabuf(lpBuffers, dwBufferCount, &outlen);
		LOQ_sockerr("network", "isiBI", "socket", s, "ip", ip, "port", port, "Buffer", lpNumberOfBytesRecvd, buf, "NumberOfBytesReceived", lpNumberOfBytesRecvd);
		if (buf)
			free(buf);
	}
	else {
		// TODO: handle completion routine case
		LOQ_sockerr("network", "isi", "socket", s, "ip", ip, "port", port);
	}
	return ret;
}

HOOKDEF(int, WSAAPI, WSASend,
    __in   SOCKET s,
    __in   LPWSABUF lpBuffers,
    __in   DWORD dwBufferCount,
    __out  LPDWORD lpNumberOfBytesSent,
    __in   DWORD dwFlags,
    __in   LPWSAOVERLAPPED lpOverlapped,
    __in   LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
) {
	// TODO: handle completion routine case
	int ret = Old_WSASend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent,
        dwFlags, lpOverlapped, lpCompletionRoutine);
	DWORD outlen;
	PVOID buf = alloc_combined_wsabuf(lpBuffers, dwBufferCount, &outlen);
	LOQ_sockerr("network", "ib", "Socket", s, "Buffer", outlen, buf);
	if (buf)
		free(buf);
    return ret;
}

HOOKDEF(int, WSAAPI, WSASendTo,
    __in   SOCKET s,
    __in   LPWSABUF lpBuffers,
    __in   DWORD dwBufferCount,
    __out  LPDWORD lpNumberOfBytesSent,
    __in   DWORD dwFlags,
    __in   const struct sockaddr *lpTo,
    __in   int iToLen,
    __in   LPWSAOVERLAPPED lpOverlapped,
    __in   LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
) {
	// TODO: handle completion routine case
	char ip[16] = { 0 };
	int port = 0;
	BOOL ret;
	DWORD outlen;
	PVOID buf;

    get_ip_port(lpTo, ip, &port);

    ret = Old_WSASendTo(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent,
        dwFlags, lpTo, iToLen, lpOverlapped, lpCompletionRoutine);
	buf = alloc_combined_wsabuf(lpBuffers, dwBufferCount, &outlen);
	LOQ_sockerr("network", "isib", "socket", s, "ip", ip, "port", port, "Buffer", outlen, buf);
	if (buf)
		free(buf);
    return ret;
}

HOOKDEF(SOCKET, WSAAPI, WSASocketA,
    __in  int af,
    __in  int type,
    __in  int protocol,
    __in  LPWSAPROTOCOL_INFO lpProtocolInfo,
    __in  GROUP g,
    __in  DWORD dwFlags
) {
    SOCKET ret = Old_WSASocketA(af, type, protocol, lpProtocolInfo, g, dwFlags);
    LOQ_sock("network", "iiii", "af", af, "type", type, "protocol", protocol, "socket", ret);
    return ret;
}

HOOKDEF(SOCKET, WSAAPI, WSASocketW,
    __in  int af,
    __in  int type,
    __in  int protocol,
    __in  LPWSAPROTOCOL_INFO lpProtocolInfo,
    __in  GROUP g,
    __in  DWORD dwFlags
) {
    SOCKET ret = Old_WSASocketW(af, type, protocol, lpProtocolInfo, g, dwFlags);
    LOQ_sock("network", "iiii", "af", af, "type", type, "protocol", protocol, "socket", ret);
    return ret;
}

HOOKDEF(int, WSAAPI, WSAConnect,
	__in   SOCKET s,
	__in   const struct sockaddr *name,
	__in   int namelen,
	__in   LPWSABUF lpCallerData,
	__out  LPWSABUF lpCalleeData,
	__in   LPQOS lpSQOS,
	__in   LPQOS lpGQOS
) {
	int ret = Old_WSAConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);
	char ip[16] = { 0 };
	int port = 0;
	get_ip_port(name, ip, &port);
	LOQ_sockerr("network", "isi", "socket", s, "ip", ip, "port", port);
	return ret;
}

HOOKDEF(BOOL, PASCAL, ConnectEx,
    _In_      SOCKET s,
    _In_      const struct sockaddr *name,
    _In_      int namelen,
    _In_opt_  PVOID lpSendBuffer,
    _In_      DWORD dwSendDataLength,
    _Out_     LPDWORD lpdwBytesSent,
    _In_      LPOVERLAPPED lpOverlapped
) {
    BOOL ret = Old_ConnectEx(s, name, namelen, lpSendBuffer, dwSendDataLength,
        lpdwBytesSent, lpOverlapped);
	char ip[16] = { 0 };
	int port = 0;
    get_ip_port(name, ip, &port);
    LOQ_bool("network", "iBsi", "socket", s, "SendBuffer", lpdwBytesSent, lpSendBuffer,
        "ip", ip, "port", port);
    return ret;
}

HOOKDEF(BOOL, PASCAL, TransmitFile,
    SOCKET hSocket,
    HANDLE hFile,
    DWORD nNumberOfBytesToWrite,
    DWORD nNumberOfBytesPerSend,
    LPOVERLAPPED lpOverlapped,
    LPTRANSMIT_FILE_BUFFERS lpTransmitBuffers,
    DWORD dwFlags
) {
    BOOL ret = Old_TransmitFile(hSocket, hFile, nNumberOfBytesToWrite,
        nNumberOfBytesPerSend, lpOverlapped, lpTransmitBuffers, dwFlags);
    LOQ_bool("network", "ipii", "socket", hSocket, "FileHandle", hFile,
        "NumberOfBytesToWrite", nNumberOfBytesToWrite,
        "NumberOfBytesPerSend", nNumberOfBytesPerSend);
    return ret;
}

HOOKDEF(int, WSAAPI, gethostname,
	_Out_ char *name,
	_In_  int  namelen
) {
	int ret = Old_gethostname(name, namelen);
	
	LOQ_sockerr("network", "s", "HostName", ret != SOCKET_ERROR && namelen ? name : NULL);

	return ret;
}

HOOKDEF(BOOL, PASCAL, WSAConnectByList,
	_In_          SOCKET               s,
	_In_          PSOCKET_ADDRESS_LIST SocketAddressList,
	_Inout_       LPDWORD              LocalAddressLength,
	_Out_         LPSOCKADDR           LocalAddress,
	_Inout_       LPDWORD              RemoteAddressLength,
	_Out_         LPSOCKADDR           RemoteAddress,
	_In_          PVOID				   timeout,
	_In_          LPWSAOVERLAPPED      Reserved
) {
	char ip[16] = { 0 };
	int port = 0;
	BOOL ret = Old_WSAConnectByList(s, SocketAddressList, LocalAddressLength, LocalAddress, RemoteAddressLength, RemoteAddress, timeout, Reserved);

	if (SocketAddressList->iAddressCount > 0)
		get_ip_port(SocketAddressList->Address[0].lpSockaddr, ip, &port);

	LOQ_bool("network", "isi", "NumberOfAddresses", SocketAddressList->iAddressCount, "ip", ip, "port", port);
	return ret;
}

HOOKDEF(BOOL, PASCAL, WSAConnectByNameW,
	_In_          SOCKET          s,
	_In_          LPWSTR          nodename,
	_In_          LPWSTR          servicename,
	_Inout_       LPDWORD         LocalAddressLength,
	_Out_         LPSOCKADDR      LocalAddress,
	_Inout_       LPDWORD         RemoteAddressLength,
	_Out_         LPSOCKADDR      RemoteAddress,
	_In_		  PVOID			  timeout,
	LPWSAOVERLAPPED Reserved
) {
	BOOL ret = Old_WSAConnectByNameW(s, nodename, servicename, LocalAddressLength, LocalAddress, RemoteAddressLength, RemoteAddress, timeout, Reserved);
	LOQ_bool("network", "uu", "NodeName", nodename, "ServiceName", servicename);
	return ret;
}

HOOKDEF(int, WSAAPI, WSASendMsg,
	_In_  SOCKET                             s,
	_In_  LPWSAMSG                           lpMsg,
	_In_  DWORD                              dwFlags,
	_Out_ LPDWORD                            lpNumberOfBytesSent,
	_In_  LPWSAOVERLAPPED                    lpOverlapped,
	_In_  LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
) {
	char ip[16] = { 0 };
	int port = 0;
	PVOID buf;
	DWORD outlen = 0;

	int ret = Old_WSASendMsg(s, lpMsg, dwFlags, lpNumberOfBytesSent, lpOverlapped, lpCompletionRoutine);
	buf = alloc_combined_wsabuf(lpMsg->lpBuffers, lpMsg->dwBufferCount, &outlen);

	get_ip_port(lpMsg->name, ip, &port);

	LOQ_sockerr("network", "Bsi", "MsgBuffer", lpNumberOfBytesSent, buf, "ip", ip, "port", port);
	return ret;
}
