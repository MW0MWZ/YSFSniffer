/*
 *   Copyright (C) 2015-2020,2023,2025 by Jonathan Naylor G4KLX
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
	LOG,
	OTHER
};

void rtrim(std::string& s) {
	while (!s.empty() && (s.back() == ' ' || s.back() == '\t' ||
	                       s.back() == '\r' || s.back() == '\n'))
		s.pop_back();
}

void ltrim(std::string& s) {
	size_t i = 0;
	while (i < s.size() && (s[i] == ' ' || s[i] == '\t'))
		++i;
	if (i > 0) s.erase(0, i);
}

void stripQuotes(std::string& s) {
	if (s.size() >= 2 && s.front() == '"' && s.back() == '"')
		s = s.substr(1, s.size() - 2);
}

} // namespace

CConf::CConf(const std::string& file) :
	m_file(file),
	m_callsign(),
	m_rptAddress("127.0.0.1"),
	m_rptPort(0U),
	m_myAddress("127.0.0.1"),
	m_myPort(0U),
	m_daemon(false),
	m_logDisplayLevel(1U)
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
		if (buffer[0] == '#' || buffer[0] == ';' ||
		    buffer[0] == '\n' || buffer[0] == '\r')
			continue;

		if (buffer[0] == '[') {
			if      (::strncmp(buffer, "[General]", 9) == 0) section = Section::GENERAL;
			else if (::strncmp(buffer, "[Log]",     5) == 0) section = Section::LOG;
			else                                             section = Section::OTHER;
			continue;
		}

		char* eq = ::strchr(buffer, '=');
		if (eq == nullptr)
			continue;
		*eq = '\0';

		std::string key   = buffer;
		std::string value = eq + 1;
		rtrim(key);   ltrim(key);
		rtrim(value); ltrim(value);
		stripQuotes(value);

		if (section == Section::GENERAL) {
			if      (key == "Callsign")     m_callsign    = value;
			else if (key == "RptAddress")   m_rptAddress  = value;
			else if (key == "RptPort")      m_rptPort     = (unsigned short)std::atoi(value.c_str());
			else if (key == "LocalAddress") m_myAddress   = value;
			else if (key == "LocalPort")    m_myPort      = (unsigned short)std::atoi(value.c_str());
			else if (key == "Daemon")       m_daemon      = std::atoi(value.c_str()) == 1;
		} else if (section == Section::LOG) {
			if      (key == "DisplayLevel") m_logDisplayLevel = (unsigned int)std::atoi(value.c_str());
		}
	}

	::fclose(fp);

	if (m_callsign.empty()) {
		::fprintf(stderr, "YSFSniffer: %s missing [General] Callsign\n", m_file.c_str());
		return false;
	}
	if (m_myPort == 0U) {
		::fprintf(stderr, "YSFSniffer: %s missing [General] LocalPort\n", m_file.c_str());
		return false;
	}
	if (m_rptPort == 0U) {
		::fprintf(stderr, "YSFSniffer: %s missing [General] RptPort\n", m_file.c_str());
		return false;
	}
	return true;
}
