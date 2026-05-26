/*
 *   Copyright (C) 2026 YSFSniffer contributors
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 */

#include "UDPListener.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

CUDPListener::CUDPListener(const std::string& address, unsigned short port) :
	m_address(address),
	m_port(port),
	m_fd(-1)
{
}

CUDPListener::~CUDPListener() {
	close();
}

bool CUDPListener::open() {
	struct addrinfo hints;
	::memset(&hints, 0, sizeof(hints));
	hints.ai_family   = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags    = AI_PASSIVE;

	char portStr[16];
	::snprintf(portStr, sizeof(portStr), "%u", (unsigned)m_port);

	struct addrinfo* res = nullptr;
	const char* host = m_address.empty() ? nullptr : m_address.c_str();
	int gai = ::getaddrinfo(host, portStr, &hints, &res);
	if (gai != 0) {
		::fprintf(stderr, "YSFSniffer: getaddrinfo(%s:%u) failed: %s\n",
		          m_address.c_str(), (unsigned)m_port, ::gai_strerror(gai));
		return false;
	}

	for (struct addrinfo* ai = res; ai != nullptr; ai = ai->ai_next) {
		int fd = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (fd < 0)
			continue;

		int yes = 1;
		::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

		if (::bind(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
			m_fd = fd;
			::freeaddrinfo(res);
			return true;
		}

		int saved = errno;
		::close(fd);
		::fprintf(stderr, "YSFSniffer: bind(%s:%u) failed: %s\n",
		          m_address.c_str(), (unsigned)m_port, ::strerror(saved));
		if (saved == EADDRINUSE)
			::fprintf(stderr,
			          "  -> another process is bound to that port "
			          "(usually YSFGateway). Stop it before running the sniffer.\n");
	}

	::freeaddrinfo(res);
	return false;
}

void CUDPListener::close() {
	if (m_fd >= 0) {
		::close(m_fd);
		m_fd = -1;
	}
}

int CUDPListener::receive(unsigned char* buffer, size_t bufferLen,
                          sockaddr_storage& addr, socklen_t& addrLen,
                          int timeoutMs) {
	if (m_fd < 0)
		return -1;

	struct pollfd pfd;
	pfd.fd     = m_fd;
	pfd.events = POLLIN;
	pfd.revents = 0;

	int pr = ::poll(&pfd, 1, timeoutMs);
	if (pr <= 0)
		return pr;

	addrLen = sizeof(addr);
	ssize_t n = ::recvfrom(m_fd, buffer, bufferLen, 0,
	                       (struct sockaddr*)&addr, &addrLen);
	if (n < 0) {
		if (errno == EINTR)
			return 0;
		::fprintf(stderr, "YSFSniffer: recvfrom failed: %s\n", ::strerror(errno));
		return -1;
	}
	return (int)n;
}
