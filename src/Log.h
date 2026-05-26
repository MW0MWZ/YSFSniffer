/*
 *   Copyright (C) 2015,2016,2020,2022,2023,2026 by Jonathan Naylor G4KLX
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

#if !defined(LOG_H)
#define LOG_H

#define	LogDebug(fmt, ...)	Log(1U, fmt, ##__VA_ARGS__)
#define	LogMessage(fmt, ...)	Log(2U, fmt, ##__VA_ARGS__)
#define	LogInfo(fmt, ...)	Log(3U, fmt, ##__VA_ARGS__)
#define	LogWarning(fmt, ...)	Log(4U, fmt, ##__VA_ARGS__)
#define	LogError(fmt, ...)	Log(5U, fmt, ##__VA_ARGS__)
#define	LogFatal(fmt, ...)	Log(6U, fmt, ##__VA_ARGS__)

extern void Log(unsigned int level, const char* fmt, ...);

extern void LogInitialise(unsigned int displayLevel);
extern void LogFinalise();

#endif
