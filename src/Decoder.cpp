/*
 *   Copyright (C) 2026 YSFSniffer contributors
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 */

#include "Decoder.h"
#include "HexDump.h"
#include "YSFDefines.h"
#include "YSFFICH.h"

#include <arpa/inet.h>
#include <cctype>
#include <chrono>
#include <cstring>
#include <ctime>
#include <netinet/in.h>

namespace {

const char* fiName(unsigned char fi) {
	switch (fi) {
	case YSF_FI_HEADER:         return "HEADER";
	case YSF_FI_COMMUNICATIONS: return "COMMS";
	case YSF_FI_TERMINATOR:     return "TERM";
	case YSF_FI_TEST:           return "TEST";
	default:                    return "?";
	}
}

const char* cmName(unsigned char cm) {
	switch (cm) {
	case YSF_CM_GROUP1:     return "GROUP1";
	case YSF_CM_GROUP2:     return "GROUP2";
	case YSF_CM_INDIVIDUAL: return "INDIVIDUAL";
	default:                return "?";
	}
}

const char* dtName(unsigned char dt) {
	switch (dt) {
	case YSF_DT_VD_MODE1:      return "V/D MODE1";
	case YSF_DT_DATA_FR_MODE:  return "DATA FR";
	case YSF_DT_VD_MODE2:      return "V/D MODE2";
	case YSF_DT_VOICE_FR_MODE: return "VOICE FR";
	default:                   return "?";
	}
}

const char* mrName(unsigned char mr) {
	switch (mr) {
	case YSF_MR_NOT_BUSY: return "NOT_BUSY";
	case YSF_MR_BUSY:     return "BUSY";
	default:              return "?";
	}
}

void timestampNow(char* out, size_t outLen) {
	using namespace std::chrono;
	auto now = system_clock::now();
	auto sec = system_clock::to_time_t(now);
	auto ms  = duration_cast<milliseconds>(now.time_since_epoch()).count() % 1000;

	struct tm tmv;
	::localtime_r(&sec, &tmv);

	::snprintf(out, outLen, "%04d-%02d-%02d %02d:%02d:%02d.%03lld",
	           tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday,
	           tmv.tm_hour, tmv.tm_min, tmv.tm_sec, (long long)ms);
}

void formatAddr(const sockaddr_storage& addr, socklen_t addrLen, char* out, size_t outLen) {
	(void)addrLen;
	if (addr.ss_family == AF_INET) {
		const sockaddr_in* sa = (const sockaddr_in*)&addr;
		char host[INET_ADDRSTRLEN];
		::inet_ntop(AF_INET, &sa->sin_addr, host, sizeof(host));
		::snprintf(out, outLen, "%s:%u", host, (unsigned)ntohs(sa->sin_port));
	} else if (addr.ss_family == AF_INET6) {
		const sockaddr_in6* sa = (const sockaddr_in6*)&addr;
		char host[INET6_ADDRSTRLEN];
		::inet_ntop(AF_INET6, &sa->sin6_addr, host, sizeof(host));
		::snprintf(out, outLen, "[%s]:%u", host, (unsigned)ntohs(sa->sin6_port));
	} else {
		::snprintf(out, outLen, "?");
	}
}

} // namespace

std::string CDecoder::trim(const unsigned char* p, size_t n) {
	std::string s((const char*)p, n);
	while (!s.empty() && (s.back() == ' ' || s.back() == 0))
		s.pop_back();
	return s;
}

CDecoder::CDecoder(FILE* out, bool decodeFICH) :
	m_out(out),
	m_decodeFICH(decodeFICH)
{
}

void CDecoder::decode(const sockaddr_storage& from, socklen_t fromLen,
                      const unsigned char* data, size_t len, uint64_t seqInSession) {
	char ts[80];
	timestampNow(ts, sizeof(ts));

	char src[80];
	formatAddr(from, fromLen, src, sizeof(src));

	std::string magic;
	if (len >= 4U)
		magic = std::string((const char*)data, 4);

	::fprintf(m_out,
	          "================================================================================\n"
	          "[%s] #%llu  from %s  len=%zu  magic=\"%s\"\n",
	          ts, (unsigned long long)seqInSession, src, len,
	          magic.empty() ? "<short>" : magic.c_str());

	if (len < 4U) {
		hexDump(m_out, data, len);
		::fputs("  (packet too short)\n\n", m_out);
		::fflush(m_out);
		return;
	}

	if      (::memcmp(data, "YSFD", 4U) == 0) decodeYSFD(data, len);
	else if (::memcmp(data, "YSFP", 4U) == 0) decodePoll(data, len);
	else if (::memcmp(data, "YSFU", 4U) == 0) decodeUnlink(data, len);
	else if (::memcmp(data, "YSFO", 4U) == 0) decodeOptions(data, len);
	else if (::memcmp(data, "YSFI", 4U) == 0) {
		::fputs("  YSFI (info) packet\n", m_out);
		hexDump(m_out, data, len, 2U);
	}
	else if (::memcmp(data, "YSFS", 4U) == 0) {
		::fputs("  YSFS (status) packet\n", m_out);
		hexDump(m_out, data, len, 2U);
	}
	else {
		::fputs("  unknown magic\n", m_out);
		hexDump(m_out, data, len, 2U);
	}

	::fputs("\n", m_out);
	::fflush(m_out);
}

void CDecoder::decodeYSFD(const unsigned char* data, size_t len) {
	if (len < 35U) {
		::fputs("  YSFD short header\n", m_out);
		hexDump(m_out, data, len, 2U);
		return;
	}

	std::string gw  = trim(data + 4U,  10U);
	std::string src = trim(data + 14U, 10U);
	std::string dst = trim(data + 24U, 10U);
	unsigned char seqFlag = data[34U];

	::fprintf(m_out,
	          "  header (35B):\n"
	          "    magic         \"YSFD\"\n"
	          "    gateway call  \"%-10s\"  (bytes 4..13)\n"
	          "    source  call  \"%-10s\"  (bytes 14..23)\n"
	          "    dest    call  \"%-10s\"  (bytes 24..33)\n"
	          "    seq/flags     0x%02x       (byte 34, bit0=EOT=%u, seq=0x%02x)\n",
	          gw.c_str(), src.c_str(), dst.c_str(),
	          seqFlag, (unsigned)(seqFlag & 0x01U), (unsigned)((seqFlag >> 1) & 0x7FU));

	::fputs("  raw packet:\n", m_out);
	hexDump(m_out, data, len, 2U);

	if (len >= 35U + YSF_FRAME_LENGTH_BYTES) {
		const unsigned char* frame = data + 35U;

		::fputs("  YSF frame (120B):\n", m_out);
		::fputs("    sync          ", m_out);
		bool syncOK = ::memcmp(frame, YSF_SYNC_BYTES, YSF_SYNC_LENGTH_BYTES) == 0;
		for (unsigned int i = 0U; i < YSF_SYNC_LENGTH_BYTES; ++i)
			::fprintf(m_out, "%02x ", frame[i]);
		::fprintf(m_out, " (%s)\n", syncOK ? "OK" : "MISMATCH");

		if (m_decodeFICH)
			decodeFICHFrame(frame);

		const unsigned char* payload = frame + YSF_SYNC_LENGTH_BYTES + YSF_FICH_LENGTH_BYTES;
		size_t payloadLen = YSF_FRAME_LENGTH_BYTES - YSF_SYNC_LENGTH_BYTES - YSF_FICH_LENGTH_BYTES;
		::fprintf(m_out, "    DCH/VCH payload (%zuB):\n", payloadLen);
		hexDump(m_out, payload, payloadLen, 6U, YSF_SYNC_LENGTH_BYTES + YSF_FICH_LENGTH_BYTES);

		scanWiresXTokens(payload, payloadLen);
	}
}

void CDecoder::decodeFICHFrame(const unsigned char* frame120) {
	const unsigned char* fichRaw = frame120 + YSF_SYNC_LENGTH_BYTES;
	::fputs("    FICH (25B raw):\n", m_out);
	hexDump(m_out, fichRaw, YSF_FICH_LENGTH_BYTES, 6U, YSF_SYNC_LENGTH_BYTES);

	CYSFFICH fich;
	bool ok = fich.decode(frame120);
	if (!ok) {
		::fputs("    FICH decode FAILED (CRC mismatch)\n", m_out);
		return;
	}

	unsigned char fi   = fich.getFI();
	unsigned char cm   = fich.getCM();
	unsigned char bn   = fich.getBN();
	unsigned char bt   = fich.getBT();
	unsigned char fn   = fich.getFN();
	unsigned char ft   = fich.getFT();
	unsigned char dt   = fich.getDT();
	unsigned char mr   = fich.getMR();
	bool          dev  = fich.getDev();
	unsigned char dgid = fich.getDGId();

	unsigned char raw[4];
	fich.getRaw(raw);

	::fprintf(m_out,
	          "    FICH decoded (raw %02x %02x %02x %02x):\n"
	          "      FI=%u (%s)  CM=%u (%s)\n"
	          "      BN=%u  BT=%u  FN=%u  FT=%u\n"
	          "      DT=%u (%s)  MR=%u (%s)  Dev=%u  DGID=%u\n",
	          raw[0], raw[1], raw[2], raw[3],
	          (unsigned)fi, fiName(fi),
	          (unsigned)cm, cmName(cm),
	          (unsigned)bn, (unsigned)bt, (unsigned)fn, (unsigned)ft,
	          (unsigned)dt, dtName(dt),
	          (unsigned)mr, mrName(mr),
	          (unsigned)dev, (unsigned)dgid);
}

void CDecoder::scanWiresXTokens(const unsigned char* payload, size_t len) {
	// Wires-X requests are framed as 5D xx 5F and responses 5D xx 5F 26 in the DCH.
	bool found = false;
	for (size_t i = 0; i + 2 < len; ++i) {
		if (payload[i] == 0x5DU && payload[i + 2] == 0x5FU) {
			if (!found) {
				::fputs("    Wires-X tokens:\n", m_out);
				found = true;
			}
			const char* name = "?";
			switch (payload[i + 1]) {
			case 0x71U: name = "DX_REQ";    break;
			case 0x23U: name = "CONN_REQ";  break;
			case 0x2AU: name = "DISC_REQ";  break;
			case 0x66U: name = "ALL_REQ";   break;
			case 0x67U: name = "CAT_REQ";   break;
			case 0x51U: name = "DX_RESP";   break;
			case 0x41U: name = "CONN/DISC_RESP"; break;
			case 0x46U: name = "ALL_RESP";  break;
			}
			::fprintf(m_out, "      offset 0x%02zx  5D %02X 5F  %s\n",
			          i, payload[i + 1], name);
		}
	}
}

void CDecoder::decodePoll(const unsigned char* data, size_t len) {
	::fputs("  YSFP (poll/link)\n", m_out);
	if (len >= 14U) {
		std::string cs = trim(data + 4U, 10U);
		::fprintf(m_out, "    callsign  \"%s\"\n", cs.c_str());
	}
	hexDump(m_out, data, len, 2U);
}

void CDecoder::decodeUnlink(const unsigned char* data, size_t len) {
	::fputs("  YSFU (unlink)\n", m_out);
	if (len >= 14U) {
		std::string cs = trim(data + 4U, 10U);
		::fprintf(m_out, "    callsign  \"%s\"\n", cs.c_str());
	}
	hexDump(m_out, data, len, 2U);
}

void CDecoder::decodeOptions(const unsigned char* data, size_t len) {
	::fputs("  YSFO (options)\n", m_out);
	if (len >= 14U) {
		std::string cs = trim(data + 4U, 10U);
		::fprintf(m_out, "    callsign  \"%s\"\n", cs.c_str());
	}
	if (len > 14U) {
		std::string opts = trim(data + 14U, len - 14U);
		::fprintf(m_out, "    options   \"%s\"\n", opts.c_str());
	}
	hexDump(m_out, data, len, 2U);
}
