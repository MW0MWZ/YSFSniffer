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
 *
 *   YSFSniffer is a stripped-down YSFGateway: it keeps only the bits
 *   needed to talk to MMDVM Host on its UDP link. Every frame received
 *   from MMDVM Host is logged via the same CUtils::dump() path that
 *   YSFGateway uses with Debug=1. The sniffer never transmits, never
 *   connects to a reflector, never processes Wires-X commands.
 */

#include "YSFSniffer.h"
#include "YSFNetwork.h"
#include "UDPSocket.h"
#include "StopWatch.h"
#include "Version.h"
#include "Thread.h"
#include "Log.h"
#include "YSFDefines.h"
#include "YSFFICH.h"
#include "GitVersion.h"

#if defined(_WIN32) || defined(_WIN64)
#include <Windows.h>
#else
#include <sys/time.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <pwd.h>
#endif

#if defined(_WIN32) || defined(_WIN64)
const char* DEFAULT_INI_FILE = "YSFGateway.ini";
#else
const char* DEFAULT_INI_FILE = "/etc/YSFGateway.ini";
#endif

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <clocale>

static CYSFSniffer* sniffer = nullptr;

static const char* fiName(unsigned char v)
{
	switch (v) {
	case YSF_FI_HEADER:         return "HEADER";
	case YSF_FI_COMMUNICATIONS: return "COMMS";
	case YSF_FI_TERMINATOR:     return "TERM";
	case YSF_FI_TEST:           return "TEST";
	}
	return "?";
}

static const char* cmName(unsigned char v)
{
	switch (v) {
	case YSF_CM_GROUP1:     return "GROUP1";
	case YSF_CM_GROUP2:     return "GROUP2";
	case YSF_CM_INDIVIDUAL: return "INDIVIDUAL";
	}
	return "?";
}

static const char* dtName(unsigned char v)
{
	switch (v) {
	case YSF_DT_VD_MODE1:      return "V/D MODE1";
	case YSF_DT_DATA_FR_MODE:  return "DATA FR";
	case YSF_DT_VD_MODE2:      return "V/D MODE2";
	case YSF_DT_VOICE_FR_MODE: return "VOICE FR";
	}
	return "?";
}

static const char* mrName(unsigned char v)
{
	switch (v) {
	case YSF_MR_NOT_BUSY: return "NOT_BUSY";
	case YSF_MR_BUSY:     return "BUSY";
	}
	return "?";
}

static bool m_killed = false;
static int  m_signal = 0;

#if !defined(_WIN32) && !defined(_WIN64)
static void sigHandler(int signum)
{
	m_killed = true;
	m_signal = signum;
}
#endif

int main(int argc, char** argv)
{
	const char* iniFile = DEFAULT_INI_FILE;
	if (argc > 1) {
		for (int currentArg = 1; currentArg < argc; ++currentArg) {
			std::string arg = argv[currentArg];
			if ((arg == "-v") || (arg == "--version")) {
				::fprintf(stdout, "YSFSniffer version %s git #%.7s\n", VERSION, gitversion);
				return 0;
			} else if (arg.substr(0, 1) == "-") {
				::fprintf(stderr, "Usage: YSFSniffer [-v|--version] [filename]\n");
				return 1;
			} else {
				iniFile = argv[currentArg];
			}
		}
	}

#if !defined(_WIN32) && !defined(_WIN64)
	::signal(SIGINT,  sigHandler);
	::signal(SIGTERM, sigHandler);
	::signal(SIGHUP,  sigHandler);
#endif

	int ret = 0;

	do {
		m_signal = 0;
		m_killed = false;

		sniffer = new CYSFSniffer(std::string(iniFile));
		ret = sniffer->run();

		delete sniffer;
		sniffer = nullptr;

		switch (m_signal) {
			case 0:
				break;
			case 2:
				::LogInfo("YSFSniffer-%s exited on receipt of SIGINT", VERSION);
				break;
			case 15:
				::LogInfo("YSFSniffer-%s exited on receipt of SIGTERM", VERSION);
				break;
			case 1:
				::LogInfo("YSFSniffer-%s is restarting on receipt of SIGHUP", VERSION);
				break;
			default:
				::LogInfo("YSFSniffer-%s exited on receipt of an unknown signal", VERSION);
				break;
		}
	} while (m_signal == 1);

	::LogFinalise();

	return ret;
}

CYSFSniffer::CYSFSniffer(const std::string& configFile) :
m_callsign(),
m_conf(configFile)
{
	CUDPSocket::startup();
}

CYSFSniffer::~CYSFSniffer()
{
	CUDPSocket::shutdown();
}

int CYSFSniffer::run()
{
	bool ret = m_conf.read();
	if (!ret) {
		::fprintf(stderr, "YSFSniffer: cannot read the .ini file\n");
		return 1;
	}

	setlocale(LC_ALL, "C");

#if !defined(_WIN32) && !defined(_WIN64)
	bool m_daemon = m_conf.getDaemon();
	if (m_daemon) {
		pid_t pid = ::fork();
		if (pid == -1) {
			::fprintf(stderr, "Couldn't fork() , exiting\n");
			return -1;
		} else if (pid != 0) {
			exit(EXIT_SUCCESS);
		}

		if (::setsid() == -1) {
			::fprintf(stderr, "Couldn't setsid(), exiting\n");
			return -1;
		}

		if (::chdir("/") == -1) {
			::fprintf(stderr, "Couldn't cd /, exiting\n");
			return -1;
		}

		if (getuid() == 0) {
			struct passwd* user = ::getpwnam("mmdvm");
			if (user == nullptr) {
				::fprintf(stderr, "Could not get the mmdvm user, exiting\n");
				return -1;
			}

			uid_t mmdvm_uid = user->pw_uid;
			gid_t mmdvm_gid = user->pw_gid;

			if (setgid(mmdvm_gid) != 0) {
				::fprintf(stderr, "Could not set mmdvm GID, exiting\n");
				return -1;
			}

			if (setuid(mmdvm_uid) != 0) {
				::fprintf(stderr, "Could not set mmdvm UID, exiting\n");
				return -1;
			}

			if (setuid(0) != -1) {
				::fprintf(stderr, "It's possible to regain root - something is wrong!, exiting\n");
				return -1;
			}
		}
	}

	if (m_daemon) {
		::close(STDIN_FILENO);
		::close(STDOUT_FILENO);
		::close(STDERR_FILENO);
	}
#endif

	if (!::LogInitialise(m_conf.getDaemon(),
	                     m_conf.getLogFilePath(),
	                     m_conf.getLogFileRoot(),
	                     m_conf.getLogFileLevel(),
	                     m_conf.getLogDisplayLevel(),
	                     m_conf.getLogFileRotate())) {
		::fprintf(stderr,
		          "YSFSniffer: cannot open log file (FilePath=%s FileRoot=%s)\n",
		          m_conf.getLogFilePath().c_str(),
		          m_conf.getLogFileRoot().c_str());
		return 1;
	}

	m_callsign = m_conf.getCallsign();

	// Force debug on. CYSFNetwork::clock() calls CUtils::dump() for every
	// inbound packet when debug=true -- that IS the air-side log.
	const bool debug = true;

	sockaddr_storage rptAddr;
	unsigned int rptAddrLen;
	if (CUDPSocket::lookup(m_conf.getRptAddress(), m_conf.getRptPort(), rptAddr, rptAddrLen) != 0) {
		::LogError("Cannot find the address of the MMDVM Host");
		return 1;
	}

	std::string myAddress = m_conf.getMyAddress();
	unsigned short myPort = m_conf.getMyPort();
	CYSFNetwork rptNetwork(myAddress, myPort, m_callsign, debug);

	ret = rptNetwork.setDestination("MMDVM", rptAddr, rptAddrLen);
	if (!ret) {
		::LogError("Cannot open the repeater network port");
		return 1;
	}

	// Passive: never transmit polls back to MMDVM Host.
	rptNetwork.stopPolling();

	CStopWatch stopWatch;
	stopWatch.start();

	LogInfo("YSFSniffer-%s is starting", VERSION);
	LogInfo("Built %s %s (GitID #%.7s)", __TIME__, __DATE__, gitversion);
	LogInfo("Listening on %s:%u for traffic from MMDVM Host at %s:%u",
	        myAddress.c_str(), (unsigned)myPort,
	        m_conf.getRptAddress().c_str(), (unsigned)m_conf.getRptPort());

	while (!m_killed) {
		unsigned char buffer[200U];

		// Drain the ring buffer. The CUtils::dump() inside
		// CYSFNetwork::clock() has already logged the raw bytes of each
		// inbound packet; here we additionally decode the YSF FICH of
		// every YSFD (data) frame so the log carries the protocol-level
		// interpretation alongside the hex dump.
		unsigned int len;
		while ((len = rptNetwork.read(buffer)) > 0U) {
			if (len >= 35U + YSF_FRAME_LENGTH_BYTES &&
			    ::memcmp(buffer, "YSFD", 4U) == 0) {
				CYSFFICH fich;
				if (fich.decode(buffer + 35U)) {
					unsigned char raw[4];
					fich.getRaw(raw);
					bool voip = (raw[2] & 0x04U) != 0U;
					LogDebug("FICH: raw=%02X %02X %02X %02X  "
					         "FI=%s CM=%s DT=%s  "
					         "BN=%u BT=%u FN=%u FT=%u  "
					         "DGID=%u  MR=%s Dev=%u VoIP=%u",
					         raw[0], raw[1], raw[2], raw[3],
					         fiName(fich.getFI()),
					         cmName(fich.getCM()),
					         dtName(fich.getDT()),
					         (unsigned)fich.getBN(),
					         (unsigned)fich.getBT(),
					         (unsigned)fich.getFN(),
					         (unsigned)fich.getFT(),
					         (unsigned)fich.getDGId(),
					         mrName(fich.getMR()),
					         (unsigned)fich.getDev(),
					         (unsigned)voip);
				} else {
					LogDebug("FICH: decode FAILED (CRC mismatch)");
				}
			}
		}

		unsigned int ms = stopWatch.elapsed();
		stopWatch.start();

		rptNetwork.clock(ms);

		if (ms < 5U)
			CThread::sleep(5U);
	}

	LogInfo("YSFSniffer is stopping");

	rptNetwork.clearDestination();

	return 0;
}
