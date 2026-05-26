/*
 *   Copyright (C) 2015,2016,2020,2022,2023,2025,2026 by Jonathan Naylor G4KLX
 *   Copyright (C) 2026 YSFSniffer contributors
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   YSFSniffer: stripped of the MQTT/JSON publish path -- this build
 *   only writes the log to stdout.
 */

#include "Log.h"

#if defined(_WIN32) || defined(_WIN64)
#include <Windows.h>
#else
#include <sys/time.h>
#include <unistd.h>
#endif

#include <cstdio>
#include <cstdlib>
#include <cstdarg>
#include <ctime>
#include <cassert>
#include <cstring>

static unsigned int m_displayLevel = 2U;

static char LEVELS[] = " DMIWEF";

void LogInitialise(unsigned int displayLevel)
{
	m_displayLevel = displayLevel;
}

void LogFinalise()
{
}

void Log(unsigned int level, const char* fmt, ...)
{
	assert(fmt != nullptr);

	char buffer[501U];
#if defined(_WIN32) || defined(_WIN64)
	SYSTEMTIME st;
	::GetSystemTime(&st);

	::sprintf(buffer, "%c: %04u-%02u-%02u %02u:%02u:%02u.%03u ",
	          LEVELS[level], st.wYear, st.wMonth, st.wDay,
	          st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
#else
	struct timeval now;
	::gettimeofday(&now, nullptr);

	struct tm* tm = ::gmtime(&now.tv_sec);

	::sprintf(buffer, "%c: %04d-%02d-%02d %02d:%02d:%02d.%03lld ",
	          LEVELS[level], tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
	          tm->tm_hour, tm->tm_min, tm->tm_sec, now.tv_usec / 1000LL);
#endif

	va_list vl;
	va_start(vl, fmt);

	::vsnprintf(buffer + ::strlen(buffer), 500 - ::strlen(buffer), fmt, vl);

	va_end(vl);

	if (level >= m_displayLevel && m_displayLevel != 0U) {
		::fprintf(stdout, "%s\n", buffer);
		::fflush(stdout);
	}

	if (level == 6U)		// Fatal
		exit(1);
}
