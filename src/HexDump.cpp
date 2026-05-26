/*
 *   Copyright (C) 2026 YSFSniffer contributors
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 */

#include "HexDump.h"

#include <cctype>

void hexDump(FILE* out, const unsigned char* data, size_t len, unsigned int indent,
             size_t startOffset) {
	const size_t WIDTH = 16U;

	for (size_t i = 0U; i < len; i += WIDTH) {
		for (unsigned int s = 0U; s < indent; ++s)
			::fputc(' ', out);

		::fprintf(out, "%08zx  ", startOffset + i);

		for (size_t j = 0U; j < WIDTH; ++j) {
			if (i + j < len)
				::fprintf(out, "%02x ", data[i + j]);
			else
				::fputs("   ", out);

			if (j == 7U)
				::fputc(' ', out);
		}

		::fputs(" |", out);
		for (size_t j = 0U; j < WIDTH; ++j) {
			if (i + j < len) {
				unsigned char c = data[i + j];
				::fputc(::isprint(c) ? c : '.', out);
			} else {
				::fputc(' ', out);
			}
		}
		::fputs("|\n", out);
	}
}
