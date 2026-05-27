/*
 *   Copyright (C) 2015,2016,2020 by Jonathan Naylor G4KLX
 *   Copyright (C) 2026 YSFSniffer contributors
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This is the pre-MQTT YSFGateway logging API (file + stdout). The
 *   MQTT publish path that was added in upstream is intentionally NOT
 *   reintroduced here -- the sniffer only needs to write the same
 *   rotating log file Pi-Star / WPSD operators already point at.
 */

#if !defined(LOG_H)
#define LOG_H

#include <string>

#define LogDebug(fmt, ...)    Log(1U, fmt, ##__VA_ARGS__)
#define LogMessage(fmt, ...)  Log(2U, fmt, ##__VA_ARGS__)
#define LogInfo(fmt, ...)     Log(3U, fmt, ##__VA_ARGS__)
#define LogWarning(fmt, ...)  Log(4U, fmt, ##__VA_ARGS__)
#define LogError(fmt, ...)    Log(5U, fmt, ##__VA_ARGS__)
#define LogFatal(fmt, ...)    Log(6U, fmt, ##__VA_ARGS__)

extern void Log(unsigned int level, const char* fmt, ...);

extern bool LogInitialise(bool daemon,
                          const std::string& filePath,
                          const std::string& fileRoot,
                          unsigned int fileLevel,
                          unsigned int displayLevel,
                          bool rotate);
extern void LogFinalise();
extern bool LogOpen();

#endif
