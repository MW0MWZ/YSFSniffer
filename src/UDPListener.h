/*
 *   Copyright (C) 2026 YSFSniffer contributors
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 */

#if !defined(YSFSNIFFER_UDPLISTENER_H)
#define YSFSNIFFER_UDPLISTENER_H

#include <cstddef>
#include <string>
#include <sys/socket.h>

class CUDPListener {
public:
	CUDPListener(const std::string& address, unsigned short port);
	~CUDPListener();

	bool open();
	void close();

	// Returns bytes read or -1 on error; fills addr/addrLen with source.
	int receive(unsigned char* buffer, size_t bufferLen,
	            sockaddr_storage& addr, socklen_t& addrLen,
	            int timeoutMs);

private:
	std::string m_address;
	unsigned short m_port;
	int m_fd;
};

#endif
