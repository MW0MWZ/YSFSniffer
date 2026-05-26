/*
 *   Copyright (C) 2016-2020,2023,2024,2025,2026 by Jonathan Naylor G4KLX
 *   Copyright (C) 2026 YSFSniffer contributors
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
 */

#if !defined(YSFSniffer_H)
#define YSFSniffer_H

#include "Conf.h"

#include <string>

class CYSFSniffer
{
public:
	explicit CYSFSniffer(const std::string& configFile);
	~CYSFSniffer();

	int run();

private:
	std::string m_callsign;
	CConf       m_conf;
};

#endif
