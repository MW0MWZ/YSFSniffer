/*
 *   Copyright (C) 2026 YSFSniffer contributors
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 */

#if !defined(YSFSNIFFER_HEXDUMP_H)
#define YSFSNIFFER_HEXDUMP_H

#include <cstddef>
#include <cstdio>

void hexDump(FILE* out, const unsigned char* data, size_t len, unsigned int indent = 0U,
             size_t startOffset = 0U);

#endif
