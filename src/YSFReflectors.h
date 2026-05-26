/*
*   Copyright (C) 2016-2020,2025,2026 by Jonathan Naylor G4KLX
*
*   This program is free software; you can redistribute it and/or modify
*   it under the terms of the GNU General Public License as published by
*   the Free Software Foundation; either version 2 of the License, or
*   (at your option) any later version.
*
*   This program is distributed in the hope that it will be useful,
*   but WITHOUT ANY WARRANTY; without even the implied warranty of
*   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*   GNU General Public License for more details.
*
*   You should have received a copy of the GNU General Public License
*   along with this program; if not, write to the Free Software
*   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#if !defined(YSFReflectors_H)
#define	YSFReflectors_H

#include "UDPSocket.h"
#include "Timer.h"

#include <vector>
#include <string>

#include <cstring>

enum class YSF_TYPE {
	YSF,
	FCS
};

class CYSFReflector {
public:
	CYSFReflector() :
	m_id(),
	m_name(),
	m_desc(),
	m_count("000"),
	m_type(YSF_TYPE::YSF),
	m_wiresX(false)
	{
		IPv4.m_addrLen = 0U;
		IPv6.m_addrLen = 0U;
	}

	CYSFReflector(const CYSFReflector& in)
	{
		m_id     = in.m_id;
		m_name   = in.m_name;
		m_desc   = in.m_desc;
		m_count  = in.m_count;
		m_type   = in.m_type;
		m_wiresX = in.m_wiresX;

		IPv4.m_addrLen = in.IPv4.m_addrLen;
		IPv6.m_addrLen = in.IPv6.m_addrLen;

		::memcpy(&IPv4.m_addr, &in.IPv4.m_addr, sizeof(sockaddr_storage));
		::memcpy(&IPv6.m_addr, &in.IPv6.m_addr, sizeof(sockaddr_storage));
	}

	bool isEmpty() const
	{
		return m_id.empty();
	}

	bool isUsed() const
	{
		return !m_id.empty();
	}

	void reset()
	{
		m_id.clear();
		m_name.clear();
	}

	bool hasIPv4() const
	{
		return IPv4.m_addrLen > 0U;
	}

	bool hasIPv6() const
	{
		return IPv6.m_addrLen > 0U;
	}

	std::string m_id;
	std::string m_name;
	std::string m_desc;
	std::string m_count;
	YSF_TYPE    m_type;
	bool        m_wiresX;
	struct {
		sockaddr_storage m_addr;
		unsigned int     m_addrLen;
	} IPv4;
	struct {
		sockaddr_storage m_addr;
		unsigned int     m_addrLen;
	} IPv6;

	CYSFReflector& operator=(const CYSFReflector& in)
	{
		if (&in != this) {
			m_id     = in.m_id;
			m_name   = in.m_name;
			m_desc   = in.m_desc;
			m_count  = in.m_count;
			m_type   = in.m_type;
			m_wiresX = in.m_wiresX;

			IPv4.m_addrLen = in.IPv4.m_addrLen;
			IPv6.m_addrLen = in.IPv6.m_addrLen;

			::memcpy(&IPv4.m_addr, &in.IPv4.m_addr, sizeof(sockaddr_storage));
			::memcpy(&IPv6.m_addr, &in.IPv6.m_addr, sizeof(sockaddr_storage));
		}

		return *this;
	}
};

// YSFSniffer: CYSFReflectors (the loader / reflector-list class) has been
// removed -- the sniffer never connects to a reflector. Only the lightweight
// CYSFReflector struct above is kept, because CYSFNetwork uses it to hold the
// MMDVM Host destination address.

#endif
