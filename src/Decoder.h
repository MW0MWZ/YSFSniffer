/*
 *   Copyright (C) 2026 YSFSniffer contributors
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 */

#if !defined(YSFSNIFFER_DECODER_H)
#define YSFSNIFFER_DECODER_H

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>
#include <sys/socket.h>

class CDecoder {
public:
	CDecoder(FILE* out, bool decodeFICH);
	~CDecoder() = default;

	void decode(const sockaddr_storage& from, socklen_t fromLen,
	            const unsigned char* data, size_t len, uint64_t seqInSession);

private:
	FILE* m_out;
	bool  m_decodeFICH;

	void decodeYSFD(const unsigned char* data, size_t len);
	void decodePoll(const unsigned char* data, size_t len);
	void decodeUnlink(const unsigned char* data, size_t len);
	void decodeOptions(const unsigned char* data, size_t len);
	void decodeFICHFrame(const unsigned char* frame120);
	void scanWiresXTokens(const unsigned char* payload, size_t len);

	static std::string trim(const unsigned char* p, size_t n);
};

#endif
