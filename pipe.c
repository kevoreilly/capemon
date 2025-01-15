/*
Cuckoo Sandbox - Automated Malware Analysis
Copyright (C) 2010-2015 Cuckoo Sandbox Developers, Optiv, Inc. (brad.spengler@optiv.com)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#include <stdio.h>
#include "ntapi.h"
#include "hooking.h"
#include "pipe.h"
#include "utf8.h"
#include "misc.h"
#include "config.h"
#include "log.h"

extern char* GetResultsPath(char* FolderName);

static int _pipe_utf8x(char **out, unsigned short x)
{
	unsigned char buf[3];
	int len = utf8_do_encode(x, buf);
	if(*out != NULL) {
		memcpy(*out, buf, len);
		*out += len;
	}
	return len;
}

static int _pipe_ascii(char **out, const char *s, int len)
{
	int ret = 0;
	while (len-- != 0) {
		ret += _pipe_utf8x(out, *(unsigned char *) s++);
	}
	return ret;
}

static int _pipe_unicode(char **out, const wchar_t *s, int len)
{
	int ret = 0;
	while (len-- != 0) {
		ret += _pipe_utf8x(out, *(unsigned short *) s++);
	}
	return ret;
}

static int _pipe_sprintf(char *out, const char *fmt, va_list args)
{
	int ret = 0;
	while (*fmt != 0) {
        if (*fmt == '%' && *(fmt + 1) == '%') {
            ret += _pipe_utf8x(&out, '%');
            fmt += 2;
            continue;
        }
        else if (*fmt != '%') {
			ret += _pipe_utf8x(&out, *fmt++);
			continue;
		}
		if(*++fmt == 'z') {
			const char *s = va_arg(args, const char *);
			if(s == NULL) return -1;

			ret += _pipe_ascii(&out, s, (int)strlen(s));
		}
		else if (*fmt == 'c') {
			char buf[2];
			buf[0] = va_arg(args, char);
			buf[1] = '\0';
			ret += _pipe_ascii(&out, buf, 1);
		}
		else if(*fmt == 'Z') {
			const wchar_t *s = va_arg(args, const wchar_t *);
			if(s == NULL) return -1;

			ret += _pipe_unicode(&out, s, lstrlenW(s));
		}
		else if (*fmt == 'F') {
			const wchar_t *s = va_arg(args, const wchar_t *);
			wchar_t *absolutepath = malloc(32768 * sizeof(wchar_t));
			if (s == NULL) return -1;
			if (absolutepath) {
				ensure_absolute_unicode_path(absolutepath, s);
				ret += _pipe_unicode(&out, absolutepath, lstrlenW(absolutepath));
				free(absolutepath);
			}
			else {
				return -1;
			}
		}
		else if (*fmt == 's') {
			int len = va_arg(args, int);
			const char *s = va_arg(args, const char *);
			if(s == NULL || !is_valid_address_range((ULONG_PTR)s, len)) return -1;

			ret += _pipe_ascii(&out, s, len < 0 ? (int)strlen(s) : len);
		}
		else if(*fmt == 'S') {
			int len = va_arg(args, int);
			const wchar_t *s = va_arg(args, const wchar_t *);
			if(s == NULL || !is_valid_address_range((ULONG_PTR)s, len)) return -1;

			ret += _pipe_unicode(&out, s, len < 0 ? lstrlenW(s) : len);
		}
		else if(*fmt == 'o') {
			UNICODE_STRING *str = va_arg(args, UNICODE_STRING *);
			if(str == NULL) return -1;

			ret += _pipe_unicode(&out, str->Buffer,
				str->Length / sizeof(wchar_t));
		}
		else if(*fmt == 'O') {
			OBJECT_ATTRIBUTES *obj = va_arg(args, OBJECT_ATTRIBUTES *);
			wchar_t path[MAX_PATH_PLUS_TOLERANCE];
			wchar_t *absolutepath;

			if(obj == NULL || obj->ObjectName == NULL) return -1;

			absolutepath = malloc(32768 * sizeof(wchar_t));
			if (absolutepath) {
				path_from_object_attributes(obj, path, (unsigned int)MAX_PATH_PLUS_TOLERANCE);

				ensure_absolute_unicode_path(absolutepath, path);

				ret += _pipe_unicode(&out, absolutepath, lstrlenW(absolutepath));
				free(absolutepath);
			}
			else {
				ret += _pipe_unicode(&out, L"", 0);
			}
		}
		else if(*fmt == 'd') {
			char s[32];
			num_to_string(s, sizeof(s), va_arg(args, int));
			ret += _pipe_ascii(&out, s, (int)strlen(s));
		}
		else if(*fmt == 'x') {
			char s[16];
			sprintf(s, "%x", va_arg(args, int));
			ret += _pipe_ascii(&out, s, (int)strlen(s));
		}
		else if (*fmt == 'p') {
			char s[18];
			sprintf(s, "%p", va_arg(args, void *));
			ret += _pipe_ascii(&out, s, (int)strlen(s));
		}
		else {
			const char *msg = "-- UNKNOWN FORMAT STRING -- ";
			ret += _pipe_ascii(&out, msg, (int)strlen(msg));
		}
		fmt++;
	}
	return ret;
}

// reminder: %s doesn't follow sprintf semantics, use %z instead
int pipe(const char *fmt, ...)
{
	va_list args;
	int len;
	int ret = -1;
	lasterror_t lasterror;

	va_start(args, fmt);

	get_lasterrors(&lasterror);

	log_flush();

	len = _pipe_sprintf(NULL, fmt, args);
	if (len > 0) {
		char *buf = calloc(1, len + 1);
		_pipe_sprintf(buf, fmt, args);

	if (g_config.standalone) {
		char pid[8];
		char* filename = GetResultsPath("pipe");
		if (filename) {
			num_to_string(pid, sizeof(pid), GetCurrentProcessId());
			strcat(filename, "\\");
			strcat(filename, pid);
			strcat(filename, ".log");
			FILE *f = fopen(filename, "ab");
			if (f) {
				fwrite(buf, len, 1, f);
				fclose(f);
				ret = 0;
			}
		}
	}
	else {
		if (CallNamedPipeW(g_config.pipe_name, buf, len, buf, len,
			(unsigned long *)&len, NMPWAIT_WAIT_FOREVER) != 0)
			ret = 0;
	}
		free(buf);
	}

	va_end(args);

	set_lasterrors(&lasterror);

	return ret;
}

int pipe2(void *out, int *outlen, const char *fmt, ...)
{
	va_list args;
	int len;
	int ret = -1;
	va_start(args, fmt);
	len = _pipe_sprintf(NULL, fmt, args);
	if(len > 0) {
		char *buf = calloc(1, len + 1);
		_pipe_sprintf(buf, fmt, args);
		va_end(args);

		if(CallNamedPipeW(g_config.pipe_name, buf, len, out, *outlen,
				(DWORD *) outlen, NMPWAIT_WAIT_FOREVER) != 0)
			ret = 0;
		free(buf);
	}
	return ret;
}
