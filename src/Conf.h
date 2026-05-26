/*
 *   Copyright (C) 2026 YSFSniffer contributors
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 */

#if !defined(YSFSNIFFER_CONF_H)
#define YSFSNIFFER_CONF_H

#include <string>

class CConf {
public:
	explicit CConf(const std::string& file);
	~CConf();

	bool read();

	// [General] (subset of YSFGateway.ini we actually care about)
	const std::string& getCallsign() const     { return m_callsign; }
	const std::string& getLocalAddress() const { return m_localAddress; }
	unsigned short     getLocalPort() const    { return m_localPort; }
	const std::string& getRptAddress() const   { return m_rptAddress; }
	unsigned short     getRptPort() const      { return m_rptPort; }

	// [Sniffer] (our own optional section)
	const std::string& getOutputFile() const   { return m_outputFile; }
	bool               getStdoutEnabled() const{ return m_stdoutEnabled; }
	bool               getDecodeFICH() const   { return m_decodeFICH; }
	bool               getOnlyYSFD() const     { return m_onlyYSFD; }
	bool               getFilterByRpt() const  { return m_filterByRpt; }

private:
	std::string    m_file;
	std::string    m_callsign;
	std::string    m_localAddress;
	unsigned short m_localPort;
	std::string    m_rptAddress;
	unsigned short m_rptPort;

	std::string    m_outputFile;
	bool           m_stdoutEnabled;
	bool           m_decodeFICH;
	bool           m_onlyYSFD;
	bool           m_filterByRpt;
};

#endif
