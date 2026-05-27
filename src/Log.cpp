/*
 *   Copyright (C) 2015,2016,2020 by Jonathan Naylor G4KLX
 *   Copyright (C) 2026 YSFSniffer contributors
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   Restored from upstream YSFGateway's pre-MQTT Log.cpp (g4klx/YSFClients
 *   commit before 651cb7d). Same file output that Pi-Star and WPSD already
 *   point at via [Log] FilePath / FileRoot / FileLevel / FileRotate.
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

static unsigned int m_fileLevel    = 2U;
static std::string  m_filePath;
static std::string  m_fileRoot;
static bool         m_fileRotate   = true;

static FILE*        m_fpLog        = nullptr;
static bool         m_daemon       = false;

static unsigned int m_displayLevel = 2U;

static struct tm    m_tm;

static char LEVELS[] = " DMIWEF";

static bool logOpenRotate()
{
	if (m_fileLevel == 0U)
		return true;

	time_t now;
	::time(&now);

	struct tm* tm = ::gmtime(&now);

	if (tm->tm_mday == m_tm.tm_mday && tm->tm_mon == m_tm.tm_mon && tm->tm_year == m_tm.tm_year) {
		if (m_fpLog != nullptr)
			return true;
	} else {
		if (m_fpLog != nullptr) {
			::fclose(m_fpLog);
			m_fpLog = nullptr;
		}
	}

	char filename[256U];
#if defined(_WIN32) || defined(_WIN64)
	::snprintf(filename, sizeof(filename), "%s\\%s-%04d-%02d-%02d.log",
	           m_filePath.c_str(), m_fileRoot.c_str(),
	           tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday);
#else
	::snprintf(filename, sizeof(filename), "%s/%s-%04d-%02d-%02d.log",
	           m_filePath.c_str(), m_fileRoot.c_str(),
	           tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday);
#endif

	m_fpLog = ::fopen(filename, "a+t");
	if (m_fpLog == nullptr) {
		::fprintf(stderr, "YSFSniffer: cannot open log file %s: %s\n",
		          filename, ::strerror(errno));
		return false;
	}

#if !defined(_WIN32) && !defined(_WIN64)
	if (m_daemon)
		::dup2(::fileno(m_fpLog), ::fileno(stderr));
#endif

	m_tm = *tm;
	return true;
}

static bool logOpenNoRotate()
{
	if (m_fileLevel == 0U)
		return true;

	if (m_fpLog != nullptr)
		return true;

	char filename[256U];
#if defined(_WIN32) || defined(_WIN64)
	::snprintf(filename, sizeof(filename), "%s\\%s.log",
	           m_filePath.c_str(), m_fileRoot.c_str());
#else
	::snprintf(filename, sizeof(filename), "%s/%s.log",
	           m_filePath.c_str(), m_fileRoot.c_str());
#endif

	m_fpLog = ::fopen(filename, "a+t");
	if (m_fpLog == nullptr) {
		::fprintf(stderr, "YSFSniffer: cannot open log file %s: %s\n",
		          filename, ::strerror(errno));
		return false;
	}

#if !defined(_WIN32) && !defined(_WIN64)
	if (m_daemon)
		::dup2(::fileno(m_fpLog), ::fileno(stderr));
#endif

	return true;
}

bool LogOpen()
{
	return m_fileRotate ? logOpenRotate() : logOpenNoRotate();
}

bool LogInitialise(bool daemon,
                   const std::string& filePath,
                   const std::string& fileRoot,
                   unsigned int fileLevel,
                   unsigned int displayLevel,
                   bool rotate)
{
	m_filePath     = filePath;
	m_fileRoot     = fileRoot;
	m_fileLevel    = fileLevel;
	m_displayLevel = displayLevel;
	m_daemon       = daemon;
	m_fileRotate   = rotate;

	if (m_daemon)
		m_displayLevel = 0U;

	return LogOpen();
}

void LogFinalise()
{
	if (m_fpLog != nullptr) {
		::fclose(m_fpLog);
		m_fpLog = nullptr;
	}
}

void Log(unsigned int level, const char* fmt, ...)
{
	assert(fmt != nullptr);

	char buffer[501U];
#if defined(_WIN32) || defined(_WIN64)
	SYSTEMTIME st;
	::GetSystemTime(&st);

	::snprintf(buffer, sizeof(buffer),
	           "%c: %04u-%02u-%02u %02u:%02u:%02u.%03u ",
	           LEVELS[level], st.wYear, st.wMonth, st.wDay,
	           st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
#else
	struct timeval now;
	::gettimeofday(&now, nullptr);

	struct tm* tm = ::gmtime(&now.tv_sec);

	::snprintf(buffer, sizeof(buffer),
	           "%c: %04d-%02d-%02d %02d:%02d:%02d.%03lld ",
	           LEVELS[level], tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
	           tm->tm_hour, tm->tm_min, tm->tm_sec, (long long)(now.tv_usec / 1000LL));
#endif

	va_list vl;
	va_start(vl, fmt);
	::vsnprintf(buffer + ::strlen(buffer),
	            sizeof(buffer) - ::strlen(buffer), fmt, vl);
	va_end(vl);

	if (m_fileLevel != 0U && level >= m_fileLevel) {
		if (LogOpen() && m_fpLog != nullptr) {
			::fprintf(m_fpLog, "%s\n", buffer);
			::fflush(m_fpLog);
		}
	}

	if (m_displayLevel != 0U && level >= m_displayLevel) {
		::fprintf(stdout, "%s\n", buffer);
		::fflush(stdout);
	}

	if (level == 6U) {		// Fatal
		if (m_fpLog != nullptr)
			::fclose(m_fpLog);
		::exit(1);
	}
}
