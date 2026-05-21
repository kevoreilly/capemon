#include "StringConversion.h"
#include <windows.h>
#include <cstring>

const char* StringConversion::ToASCII(const wchar_t* str, char* buf, size_t bufsize)
{
	if (!buf || bufsize == 0) {
		return buf;
	}

	if (!str) {
		buf[0] = '\0';
		return buf;
	}

	int req = WideCharToMultiByte(CP_UTF8, 0, str, -1, NULL, 0, NULL, NULL);
	if (req <= 0) {
		buf[0] = '\0';
		return buf;
	}

	if ((size_t)req <= bufsize) {
		WideCharToMultiByte(CP_UTF8, 0, str, -1, buf, (int)bufsize, NULL, NULL);
		return buf;
	}

	char* temp = new char[req];
	WideCharToMultiByte(CP_UTF8, 0, str, -1, temp, req, NULL, NULL);

	size_t max_bytes = bufsize - 1;
	size_t truncate_len = max_bytes;

	if (truncate_len > 0) {
		size_t L = truncate_len - 1;
		while (L > 0 && (temp[L] & 0xC0) == 0x80) {
			L--;
		}

		unsigned char lead = (unsigned char)temp[L];
		size_t expected = 1;
		if ((lead & 0x80) == 0) expected = 1;
		else if ((lead & 0xE0) == 0xC0) expected = 2;
		else if ((lead & 0xF0) == 0xE0) expected = 3;
		else if ((lead & 0xF8) == 0xF0) expected = 4;

		if (max_bytes - L < expected) {
			truncate_len = L;
		}
	}

	memcpy(buf, temp, truncate_len);
	buf[truncate_len] = '\0';

	delete[] temp;
	return buf;
}

const wchar_t* StringConversion::ToUTF16(const char* str, wchar_t* buf, size_t bufsize)
{
	if (!buf || bufsize == 0) {
		return buf;
	}

	if (!str) {
		buf[0] = L'\0';
		return buf;
	}

	int req = MultiByteToWideChar(CP_UTF8, 0, str, -1, NULL, 0);
	if (req <= 0) {
		buf[0] = L'\0';
		return buf;
	}

	if ((size_t)req <= bufsize) {
		MultiByteToWideChar(CP_UTF8, 0, str, -1, buf, (int)bufsize);
		return buf;
	}

	wchar_t* temp = new wchar_t[req];
	MultiByteToWideChar(CP_UTF8, 0, str, -1, temp, req);

	size_t max_chars = bufsize - 1;
	size_t truncate_len = max_chars;

	if (truncate_len > 0) {
		wchar_t last = temp[truncate_len - 1];
		if (last >= 0xD800 && last <= 0xDBFF) {
			truncate_len--;
		}
	}

	memcpy(buf, temp, truncate_len * sizeof(wchar_t));
	buf[truncate_len] = L'\0';

	delete[] temp;
	return buf;
}
