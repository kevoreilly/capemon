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

	size_t len = 0;
	while (str[len] && len < bufsize - 1) len++;

	int written = WideCharToMultiByte(CP_UTF8, 0, str, (int)len, buf, (int)bufsize - 1, NULL, NULL);
	if (written >= 0) {
		buf[written] = '\0';
	} else {
		buf[0] = '\0';
	}

	buf[bufsize - 1] = '\0';
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

	size_t len = 0;
	while (str[len] && len < bufsize - 1) len++;

	int written = MultiByteToWideChar(CP_UTF8, 0, str, (int)len, buf, (int)bufsize - 1);
	if (written >= 0) {
		buf[written] = L'\0';
	} else {
		buf[0] = L'\0';
	}

	buf[bufsize - 1] = L'\0';
	return buf;
}
