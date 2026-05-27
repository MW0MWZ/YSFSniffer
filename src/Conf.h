/*
 *   Copyright (C) 2015-2020,2023,2025 by Jonathan Naylor G4KLX
 *   Copyright (C) 2026 YSFSniffer contributors
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   READ-ONLY parser for an existing YSFGateway.ini.  Reads only the
 *   handful of keys YSFSniffer needs and silently ignores everything
 *   else in the file -- it never writes the INI back.
 */

#if !defined(CONF_H)
#define CONF_H

#include <string>

class CConf
{
public:
	explicit CConf(const std::string& file);
	~CConf();

	bool read();

	// [General]
	const std::string&  getCallsign()   const { return m_callsign; }
	const std::string&  getRptAddress() const { return m_rptAddress; }
	unsigned short      getRptPort()    const { return m_rptPort; }
	const std::string&  getMyAddress()  const { return m_myAddress; }
	unsigned short      getMyPort()     const { return m_myPort; }
	bool                getDaemon()     const { return m_daemon; }

	// [Log]
	unsigned int        getLogFileLevel()    const { return m_logFileLevel; }
	const std::string&  getLogFilePath()     const { return m_logFilePath; }
	const std::string&  getLogFileRoot()     const { return m_logFileRoot; }
	bool                getLogFileRotate()   const { return m_logFileRotate; }
	unsigned int        getLogDisplayLevel() const { return m_logDisplayLevel; }

private:
	std::string    m_file;
	std::string    m_callsign;
	std::string    m_rptAddress;
	unsigned short m_rptPort;
	std::string    m_myAddress;
	unsigned short m_myPort;
	bool           m_daemon;

	unsigned int   m_logFileLevel;
	std::string    m_logFilePath;
	std::string    m_logFileRoot;
	bool           m_logFileRotate;
	unsigned int   m_logDisplayLevel;
};

#endif
