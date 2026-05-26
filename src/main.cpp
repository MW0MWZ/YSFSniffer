/*
 *   Copyright (C) 2026 YSFSniffer contributors
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   Reads a YSFGateway.ini file, binds passively to the same UDP port
 *   YSFGateway uses, and writes annotated hex dumps of every YSF UDP
 *   packet it sees for off-line reverse engineering. Never transmits.
 */

#include "Conf.h"
#include "Decoder.h"
#include "UDPListener.h"

#include <arpa/inet.h>
#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <netdb.h>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>

static const char* kVersion = "0.1.0";

static std::atomic<bool> g_stop{false};
static std::atomic<int>  g_signal{0};

static void onSignal(int sig) {
	g_signal = sig;
	g_stop   = true;
}

static bool addrMatches(const sockaddr_storage& a,
                        const std::string& host, unsigned short port) {
	struct addrinfo hints;
	::memset(&hints, 0, sizeof(hints));
	hints.ai_family   = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;

	char portStr[16];
	::snprintf(portStr, sizeof(portStr), "%u", (unsigned)port);

	struct addrinfo* res = nullptr;
	if (::getaddrinfo(host.c_str(), portStr, &hints, &res) != 0)
		return false;

	bool match = false;
	for (struct addrinfo* ai = res; ai != nullptr; ai = ai->ai_next) {
		if (ai->ai_family != a.ss_family)
			continue;

		if (a.ss_family == AF_INET) {
			const sockaddr_in* x = (const sockaddr_in*)&a;
			const sockaddr_in* y = (const sockaddr_in*)ai->ai_addr;
			if (x->sin_addr.s_addr == y->sin_addr.s_addr) { match = true; break; }
		} else if (a.ss_family == AF_INET6) {
			const sockaddr_in6* x = (const sockaddr_in6*)&a;
			const sockaddr_in6* y = (const sockaddr_in6*)ai->ai_addr;
			if (::memcmp(&x->sin6_addr, &y->sin6_addr, sizeof(x->sin6_addr)) == 0) {
				match = true; break;
			}
		}
	}
	::freeaddrinfo(res);
	return match;
}

static void usage(FILE* out) {
	::fprintf(out,
	          "YSFSniffer %s\n"
	          "Usage: YSFSniffer [-v|--version] [-h|--help] <YSFGateway.ini>\n"
	          "\n"
	          "Reads the [General] LocalAddress/LocalPort from the YSFGateway INI,\n"
	          "binds passively to that UDP socket, and dumps every datagram it sees.\n"
	          "YSFGateway must be stopped while this runs (UDP port conflict).\n",
	          kVersion);
}

int main(int argc, char** argv) {
	std::string iniPath;
	for (int i = 1; i < argc; ++i) {
		std::string a = argv[i];
		if (a == "-v" || a == "--version") {
			::fprintf(stdout, "YSFSniffer %s\n", kVersion);
			return 0;
		}
		if (a == "-h" || a == "--help") {
			usage(stdout);
			return 0;
		}
		if (!a.empty() && a[0] == '-') {
			usage(stderr);
			return 1;
		}
		iniPath = a;
	}

	if (iniPath.empty()) {
		usage(stderr);
		return 1;
	}

	CConf conf(iniPath);
	if (!conf.read())
		return 1;

	FILE* logFile = nullptr;
	if (!conf.getOutputFile().empty()) {
		logFile = ::fopen(conf.getOutputFile().c_str(), "a");
		if (logFile == nullptr) {
			::fprintf(stderr, "YSFSniffer: cannot open output file %s: %s\n",
			          conf.getOutputFile().c_str(), ::strerror(errno));
			return 1;
		}
	}

	FILE* out = logFile != nullptr ? logFile : stdout;
	if (conf.getStdoutEnabled() && logFile != nullptr) {
		::setvbuf(stdout, nullptr, _IOLBF, 0);
	}

	::signal(SIGINT,  onSignal);
	::signal(SIGTERM, onSignal);
	::signal(SIGHUP,  onSignal);
	::signal(SIGPIPE, SIG_IGN);

	::fprintf(out,
	          "# YSFSniffer %s started\n"
	          "# ini=%s\n"
	          "# bind=%s:%u\n"
	          "# expected sender (RptAddress)=%s:%u  (filter=%s)\n"
	          "# callsign=%s\n"
	          "# decodeFICH=%d  onlyYSFD=%d\n"
	          "\n",
	          kVersion, iniPath.c_str(),
	          conf.getLocalAddress().c_str(), (unsigned)conf.getLocalPort(),
	          conf.getRptAddress().c_str(), (unsigned)conf.getRptPort(),
	          conf.getFilterByRpt() ? "on" : "off",
	          conf.getCallsign().c_str(),
	          (int)conf.getDecodeFICH(), (int)conf.getOnlyYSFD());
	::fflush(out);

	CUDPListener listener(conf.getLocalAddress(), conf.getLocalPort());
	if (!listener.open()) {
		if (logFile != nullptr) ::fclose(logFile);
		return 1;
	}

	CDecoder decoder(out, conf.getDecodeFICH());

	unsigned char buffer[2048];
	uint64_t count = 0U;

	while (!g_stop) {
		sockaddr_storage from;
		socklen_t fromLen = sizeof(from);
		::memset(&from, 0, sizeof(from));

		int n = listener.receive(buffer, sizeof(buffer), from, fromLen, 250);
		if (n < 0)
			break;
		if (n == 0)
			continue;

		if (conf.getFilterByRpt() &&
		    !addrMatches(from, conf.getRptAddress(), conf.getRptPort()))
			continue;

		if (conf.getOnlyYSFD() && (n < 4 || ::memcmp(buffer, "YSFD", 4) != 0))
			continue;

		decoder.decode(from, fromLen, buffer, (size_t)n, ++count);
	}

	::fprintf(out, "\n# YSFSniffer stopping (signal=%d, frames=%llu)\n",
	          (int)g_signal.load(), (unsigned long long)count);
	::fflush(out);

	listener.close();
	if (logFile != nullptr)
		::fclose(logFile);

	return 0;
}
