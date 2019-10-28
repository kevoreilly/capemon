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
#include "config.h"
#include "misc.h"
#include "log.h"
#include "hooking.h"
#include "Shlwapi.h"

extern void DoOutputDebugString(_In_ LPCTSTR lpOutputString, ...);
extern char *our_dll_path;
extern wchar_t *our_process_path_w;
extern PVOID bp0, bp1, bp2, bp3;
#ifdef CAPE_TRACE
extern int TraceDepthLimit, EntryPointRegister;
extern unsigned int StepLimit;
#endif

int read_config(void)
{
    char buf[32768], config_fname[MAX_PATH], analyzer_path[MAX_PATH];
	FILE *fp;
	unsigned int i;
	unsigned int vallen;

    // look for the config in analyzer directory
    strncpy(analyzer_path, our_dll_path, strlen(our_dll_path));
    PathRemoveFileSpec(analyzer_path); // remove filename
    PathRemoveFileSpec(analyzer_path); // remove dll folder
    sprintf(config_fname, "%s\\%u.ini", analyzer_path, GetCurrentProcessId());

    fp = fopen(config_fname, "r");

    // backward compatibility
	if (fp == NULL) {
        memset(config_fname, 0, sizeof(config_fname));
        sprintf(config_fname, "C:\\%u.ini", GetCurrentProcessId());
		fp = fopen(config_fname, "r");
    }

    // for debugging purposes
    if (fp == NULL) {
        memset(config_fname, 0, sizeof(config_fname));
        sprintf(config_fname, "%s\\config.ini", analyzer_path);
		fp = fopen(config_fname, "r");
		if (fp == NULL)
			return 0;
	}

	g_config.force_sleepskip = -1;
#ifdef _WIN64
	g_config.hook_type = HOOK_JMP_INDIRECT;
#else
	g_config.hook_type = HOOK_HOTPATCH_JMP_INDIRECT;
#endif
    g_config.procdump = 0;
    g_config.procmemdump = 0;

#ifdef CAPE_TRACE
    EntryPointRegister = 0;
#endif

	memset(buf, 0, sizeof(buf));
	while (fgets(buf, sizeof(buf), fp) != NULL)
	{
        // cut off the newline
        char *p = strchr(buf, '\r');
        if(p != NULL) *p = 0;
        p = strchr(buf, '\n');
        if(p != NULL) *p = 0;

        // split key=value
        p = strchr(buf, '=');
        if(p != NULL) {
			const char *key = buf;
			char *value = p + 1;

			*p = 0;
			vallen = (unsigned int)strlen(value);
            if(!strcmp(key, "pipe")) {
				for (i = 0; i < vallen; i++)
					g_config.pipe_name[i] = (wchar_t)(unsigned short)value[i];
            }
			else if (!strcmp(key, "logserver")) {
				strncpy(g_config.logserver, value,
					ARRAYSIZE(g_config.logserver));
			}
			else if (!strcmp(key, "results")) {
                strncpy(g_config.results, value,
                    ARRAYSIZE(g_config.results) - 1);
				for (i = 0; i < ARRAYSIZE(g_config.results); i++)
					g_config.w_results[i] = (wchar_t)(unsigned short)g_config.results[i];
			}
			else if (!strcmp(key, "file-of-interest")) {
				unsigned int len = (unsigned int)strlen(value);
				if (len > 1) {
					if (value[1] == ':') {
						// is a file
						char *tmp = calloc(1, MAX_PATH);

						ensure_absolute_ascii_path(tmp, value);
						g_config.file_of_interest = ascii_to_unicode_dup(tmp);
						free(tmp);
						// if the file of interest is our own executable, then don't do any special handling
						if (wcsicmp(our_process_path_w, g_config.file_of_interest))
							g_config.suspend_logging = TRUE;
					}
					else {
						// is a URL
						g_config.url_of_interest = ascii_to_unicode_dup(value);
						g_config.suspend_logging = TRUE;
					}
				}
			}
			else if (!strcmp(key, "referrer")) {
				g_config.w_referrer = ascii_to_unicode_dup(value);
				g_config.referrer = strdup(value);
			}
			else if (!strcmp(key, "analyzer")) {
                strncpy(g_config.analyzer, value,
                    ARRAYSIZE(g_config.analyzer)-1);
				for (i = 0; i < ARRAYSIZE(g_config.analyzer); i++)
					g_config.w_analyzer[i] = (wchar_t)(unsigned short)g_config.analyzer[i];
				wcscpy(g_config.dllpath, g_config.w_analyzer);
				if (wcslen(g_config.dllpath) < ARRAYSIZE(g_config.dllpath) - 5)
					wcscat(g_config.dllpath, L"\\dll\\");
            }
            else if(!strcmp(key, "shutdown-mutex")) {
                strncpy(g_config.shutdown_mutex, value,
                    ARRAYSIZE(g_config.shutdown_mutex));
            }
            else if(!strcmp(key, "first-process")) {
                g_config.first_process = value[0] == '1';
            }
            else if(!strcmp(key, "startup-time")) {
                g_config.startup_time = atoi(value);
            }
			else if (!strcmp(key, "debug")) {
				g_config.debug = atoi(value);
			}
			else if (!strcmp(key, "hook-type")) {
#ifndef _WIN64
				if (!strcmp(value, "direct"))
					g_config.hook_type = HOOK_JMP_DIRECT;
				else if (!strcmp(value, "indirect"))
					g_config.hook_type = HOOK_JMP_INDIRECT;
				else if (!strcmp(value, "safe"))
					g_config.hook_type = HOOK_SAFEST;
#endif
			}
			else if (!strcmp(key, "disable_hook_content")) {
				g_config.disable_hook_content = atoi(value);
			}
			/*
			else if(!strcmp(key, "host-ip")) {
                g_config.host_ip = inet_addr(value);
            }
            else if(!strcmp(key, "host-port")) {
                g_config.host_port = atoi(value);
            }
			*/
            else if(!strcmp(key, "force-sleepskip")) {
                g_config.force_sleepskip = value[0] == '1';
            }
			else if (!strcmp(key, "serial")) {
				g_config.serial_number = (unsigned int)strtoul(value, NULL, 16);
			}
			else if (!strcmp(key, "sysvol_ctimelow")) {
				g_config.sysvol_ctime.dwLowDateTime = (unsigned int)strtoul(value, NULL, 16);
			}
			else if (!strcmp(key, "sysvol_ctimehigh")) {
				g_config.sysvol_ctime.dwHighDateTime = (unsigned int)strtoul(value, NULL, 16);
			}
			else if (!strcmp(key, "sys32_ctimelow")) {
				g_config.sys32_ctime.dwLowDateTime = (unsigned int)strtoul(value, NULL, 16);
			}
			else if (!strcmp(key, "sys32_ctimehigh")) {
				g_config.sys32_ctime.dwHighDateTime = (unsigned int)strtoul(value, NULL, 16);
			}
			else if (!strcmp(key, "full-logs")) {
				g_config.full_logs = value[0] == '1';
			}
			else if (!strcmp(key, "force-flush")) {
				g_config.force_flush = atoi(value);
			}
			else if (!strcmp(key, "terminate-event")) {
				strncpy(g_config.terminate_event_name, value,
					ARRAYSIZE(g_config.terminate_event_name));
			}
			else if (!strcmp(key, "no-stealth")) {
				g_config.no_stealth = value[0] == '1';
			}
			else if (!strcmp(key, "buffer-max")) {
				buffer_log_max = (unsigned int)strtoul(value, NULL, 10);
			}
			else if (!strcmp(key, "large-buffer-max")) {
				large_buffer_log_max = (unsigned int)strtoul(value, NULL, 10);
			}
			else if (!strcmp(key, "exclude-apis")) {
				unsigned int x = 0;
				char *p2;
				p = value;
				while (p && x < EXCLUSION_MAX) {
					p2 = strchr(p, ':');
					if (p2) {
						*p2 = '\0';
					}
					g_config.excluded_apinames[x++] = strdup(p);
					if (p2 == NULL)
						break;
					p = p2 + 1;
				}
			}
			else if (!strcmp(key, "exclude-dlls")) {
				unsigned int x = 0;
				char *p2;
				p = value;
				while (p && x < EXCLUSION_MAX) {
					p2 = strchr(p, ':');
					if (p2) {
						*p2 = '\0';
					}
					g_config.excluded_dllnames[x++] = ascii_to_unicode_dup(p);
					if (p2 == NULL)
						break;
					p = p2 + 1;
				}
			}
			else if (!strcmp(key, "base-on-api")) {
				unsigned int x = 0;
				char *p2;
				p = value;
				while (p && x < EXCLUSION_MAX) {
					p2 = strchr(p, ':');
					if (p2) {
						*p2 = '\0';
					}
					g_config.base_on_apiname[x++] = strdup(p);
                    DoOutputDebugString("Added '%s' to base-on-API list.\n", p);
					if (p2 == NULL)
						break;
					p = p2 + 1;
				}
			}
			else if (!strcmp(key, "dump-on-api")) {
				unsigned int x = 0;
				char *p2;
				p = value;
				while (p && x < EXCLUSION_MAX) {
					p2 = strchr(p, ':');
					if (p2) {
						*p2 = '\0';
					}
					g_config.dump_on_apinames[x++] = strdup(p);
                    DoOutputDebugString("Added '%s' to dump-on-API list.\n", p);
					if (p2 == NULL)
						break;
					p = p2 + 1;
				}
			}
#ifdef CAPE_TRACE
            else if (!strcmp(key, "bp0")) {
                if (!strncmp(value, "ep", 2)) {
                    DoOutputDebugString("bp0 set to entry point.\n", bp0);
                    EntryPointRegister = 1;
                }
                else {
                    bp0 = (PVOID)(DWORD_PTR)strtoul(value, NULL, 0);
                    DoOutputDebugString("bp0 set to 0x%x.\n", bp0);
                }
			}
            else if (!strcmp(key, "bp1")) {
                if (!strncmp(value, "ep", 2)) {
                    DoOutputDebugString("bp1 set to entry point.\n", bp1);
                    EntryPointRegister = 2;
                }
                else {
                    bp1 = (PVOID)(DWORD_PTR)strtoul(value, NULL, 0);
                    DoOutputDebugString("bp1 set to 0x%x.\n", bp1);
                }
			}
            else if (!strcmp(key, "bp2")) {
                if (!strncmp(value, "ep", 2)) {
                    DoOutputDebugString("bp2 set to entry point.\n", bp2);
                    EntryPointRegister = 3;
                }
                else {
                    bp2 = (PVOID)(DWORD_PTR)strtoul(value, NULL, 0);
                    DoOutputDebugString("bp2 set to 0x%x.\n", bp2);
                }
			}
            else if (!strcmp(key, "bp3")) {
                if (!strncmp(value, "ep", 2)) {
                    DoOutputDebugString("bp3 set to entry point.\n", bp3);
                    EntryPointRegister = 4;
                }
                else {
                    bp3 = (PVOID)(DWORD_PTR)strtoul(value, NULL, 0);
                    DoOutputDebugString("bp3 set to 0x%x.\n", bp3);
                }
			}
            else if (!strcmp(key, "depth")) {
				TraceDepthLimit = (int)strtoul(value, NULL, 10);
                DoOutputDebugString("Trace depth set to 0x%x", TraceDepthLimit);
			}
            else if (!strcmp(key, "count")) {
				StepLimit = (unsigned int)strtoul(value, NULL, 10);
                DoOutputDebugString("Trace instruction count set to 0x%x", StepLimit);
			}
#endif
            else if (!strcmp(key, "procdump")) {
				g_config.procdump = value[0] == '1';
                if (g_config.procdump)
                    DoOutputDebugString("Process dumps enabled.\n");
                else
                    DoOutputDebugString("Process dumps disabled.\n");
			}
            else if (!strcmp(key, "procmemdump")) {
				// for backwards compatibility with spender
                if (!strcmp(value, "yes"))
                    g_config.procmemdump = 1;
                else
                    g_config.procmemdump = value[0] == '1';
                if (g_config.procmemdump)
                    DoOutputDebugString("Full process memory dumps enabled.\n");
                else
                    DoOutputDebugString("Full process memory dumps disabled.\n");
			}
            else if (!strcmp(key, "import_reconstruction")) {
				g_config.import_reconstruction = value[0] == '1';
                if (g_config.import_reconstruction)
                    DoOutputDebugString("Import reconstruction of process dumps enabled.\n");
                else
                    DoOutputDebugString("Import reconstruction of process dumps disabled.\n");
			}
            else if (!strcmp(key, "terminate-processes")) {
				g_config.terminate_processes = value[0] == '1';
                if (g_config.terminate_processes)
                    DoOutputDebugString("Terminate processes on terminate_event enabled.\n");
                else
                    DoOutputDebugString("Terminate processes on terminate_event disabled.\n");
			}
            else if (!strcmp(key, "verbose-dumping")) {
				g_config.verbose_dumping = value[0] == '1';
                if (g_config.verbose_dumping)
                    DoOutputDebugString("Verbose dumping enabled.\n");
			}
            else if (!strcmp(key, "dump-config-region")) {
				g_config.dump_config_region = value[0] == '1';
                if (g_config.dump_config_region)
                    DoOutputDebugString("Dump config region enabled.\n");
			}
            else if (!strcmp(key, "single-process")) {
				g_config.single_process = value[0] == '1';
                if (g_config.single_process)
                    DoOutputDebugString("Monitoring child processes disabled.\n");
			}
            else DoOutputDebugString("CAPE debug - unrecognised key %s.\n", key);
		}
    }

	/* don't suspend logging if this isn't the first process or if we want all the logs */
	if (!g_config.first_process || g_config.full_logs)
		g_config.suspend_logging = FALSE;

	fclose(fp);
    DeleteFileA(config_fname);
	return 1;
}
