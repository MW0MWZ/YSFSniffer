/*
 *   Copyright (C) 2026 YSFSniffer contributors
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 */

#include "Conf.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cctype>

namespace {

enum class Section {
	NONE,
	GENERAL,
	SNIFFER,
	OTHER
};

void rtrim(std::string& s) {
	while (!s.empty() && (s.back() == ' ' || s.back() == '\t' ||
	                       s.back() == '\r' || s.back() == '\n'))
		s.pop_back();
}

void stripQuotes(std::string& s) {
	if (s.size() >= 2 && s.front() == '"' && s.back() == '"')
		s = s.substr(1, s.size() - 2);
}

bool asBool(const std::string& v) {
	return v == "1" || v == "true" || v == "TRUE" || v == "yes" || v == "YES";
}

} // namespace

CConf::CConf(const std::string& file) :
	m_file(file),
	m_callsign(),
	m_localAddress("127.0.0.1"),
	m_localPort(0U),
	m_rptAddress("127.0.0.1"),
	m_rptPort(0U),
	m_outputFile(),
	m_stdoutEnabled(true),
	m_decodeFICH(true),
	m_onlyYSFD(false),
	m_filterByRpt(false)
{
}

CConf::~CConf() = default;

bool CConf::read() {
	FILE* fp = ::fopen(m_file.c_str(), "rt");
	if (fp == nullptr) {
		::fprintf(stderr, "YSFSniffer: cannot open ini file - %s\n", m_file.c_str());
		return false;
	}

	Section section = Section::NONE;
	char buffer[512];

	while (::fgets(buffer, sizeof(buffer), fp) != nullptr) {
		if (buffer[0] == '#' || buffer[0] == ';' || buffer[0] == '\n' || buffer[0] == '\r')
			continue;

		if (buffer[0] == '[') {
			if (::strncmp(buffer, "[General]", 9) == 0)
				section = Section::GENERAL;
			else if (::strncmp(buffer, "[Sniffer]", 9) == 0)
				section = Section::SNIFFER;
			else
				section = Section::OTHER;
			continue;
		}

		char* eq = ::strchr(buffer, '=');
		if (eq == nullptr)
			continue;

		*eq = '\0';
		std::string key   = buffer;
		std::string value = eq + 1;

		rtrim(key);
		rtrim(value);
		while (!key.empty() && (key.front() == ' ' || key.front() == '\t'))
			key.erase(key.begin());
		while (!value.empty() && (value.front() == ' ' || value.front() == '\t'))
			value.erase(value.begin());
		stripQuotes(value);

		if (section == Section::GENERAL) {
			if      (key == "Callsign")     m_callsign     = value;
			else if (key == "LocalAddress") m_localAddress = value;
			else if (key == "LocalPort")    m_localPort    = (unsigned short)std::atoi(value.c_str());
			else if (key == "RptAddress")   m_rptAddress   = value;
			else if (key == "RptPort")      m_rptPort      = (unsigned short)std::atoi(value.c_str());
		} else if (section == Section::SNIFFER) {
			if      (key == "OutputFile")   m_outputFile    = value;
			else if (key == "Stdout")       m_stdoutEnabled = asBool(value);
			else if (key == "DecodeFICH")   m_decodeFICH    = asBool(value);
			else if (key == "OnlyYSFD")     m_onlyYSFD      = asBool(value);
			else if (key == "FilterByRpt")  m_filterByRpt   = asBool(value);
		}
	}

	::fclose(fp);

	if (m_localPort == 0U) {
		::fprintf(stderr, "YSFSniffer: [General] LocalPort missing or zero\n");
		return false;
	}
	if (m_callsign.empty()) {
		::fprintf(stderr, "YSFSniffer: [General] Callsign missing\n");
		return false;
	}

	return true;
}
