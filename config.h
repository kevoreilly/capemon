#ifndef __CONFIG_H
#define __CONFIG_H

/*
Cuckoo Sandbox - Automated Malware Analysis
Copyright (C) 2010-2012 Cuckoo Sandbox Developers

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

#define EXCLUSION_MAX 128

struct _g_config {
    // name of the pipe to communicate with cuckoo
    wchar_t pipe_name[MAX_PATH];

	char logserver[MAX_PATH];

    // results directory, has to be hidden
    char results[MAX_PATH];

	// results directory, has to be hidden
	wchar_t w_results[MAX_PATH];

	// analyzer directory, has to be hidden
    char analyzer[MAX_PATH];

	// analyzer directory, has to be hidden
	wchar_t w_analyzer[MAX_PATH];

	// python directory, has to be hidden
    char pythonpath[MAX_PATH];

	// python directory, has to be hidden
	wchar_t w_pythonpath[MAX_PATH];

	// cuckoomon DLL directory
	wchar_t dllpath[MAX_PATH];

	// file of interest
	wchar_t *file_of_interest;

	// URL of interest
	wchar_t *url_of_interest;

	// Referrer for initial URL request
	wchar_t *w_referrer;
	char *referrer;

	// if this mutex exists then we're shutting down
    char shutdown_mutex[MAX_PATH];

	// event set by analyzer when our process is potentially going to be terminated
	// cuckoomon itself will flush logs at this point, but the analyzer may take additional
	// actions, like process dumping
	char terminate_event_name[MAX_PATH];

    // is this the first process or not?
    int first_process;

	// do we want to ignore "file of interest" and other forms of log reduction?
	int full_logs;

	// should we attempt anti-anti-sandbox/VM tricks ?
	int no_stealth;

    // how many milliseconds since startup
    unsigned int startup_time;

	// system volume serial number (for reproducing Milicenso)
	unsigned int serial_number;

	// system32 create time (for reproducing Milicenso)
	FILETIME sys32_ctime;

	// system volume information create time (for reproducing Milicenso)
	FILETIME sysvol_ctime;

    // do we force sleep-skipping despite threads?
    int force_sleepskip;

	// do we force flushing of each log?
	int force_flush;

	// Debugging level (1 = display exceptions, 2 = display all exceptions)
	int debug;

	// Default hook type (may be overridden for specific functions)
	int hook_type;

	// Disable hook content
	int disable_hook_content;

    // server ip and port
    //unsigned int host_ip;
    //unsigned short host_port;

	// Dropped files limit
	unsigned int dropped_limit;

	BOOLEAN suspend_logging;

	char *excluded_apinames[EXCLUSION_MAX];
	wchar_t *excluded_dllnames[EXCLUSION_MAX];
	char *base_on_apiname[EXCLUSION_MAX];
 	char *dump_on_apinames[EXCLUSION_MAX];
    int dump_on_api_type;

    // behavioural payload extraction options
    int compression;
    int extraction;
    int injection;

    // should we dump each process on exit/analysis timeout?
    int procdump;
    int procmemdump;

    // should we attempt import reconstruction on each process dump? (slow)
    int import_reconstruction;

    // should we terminate processes after dumping on terminate_event?
    int terminate_processes;

    // dump all calling regions immediately
    int verbose_dumping;

    // dump regions containing c2
    int dump_config_region;

    // prevent monitoring child processes
    int single_process;

    // for monitor testing
    int stand_alone;

    // for dumping of crypto API buffers
    int dump_crypto;

    // for Hancitor config & payload extraction
    int hancitor;

#ifdef CAPE_TRACE
	char *break_on_apiname;
	char *break_on_modname;
    char break_on_return[MAX_PATH];
    BOOLEAN break_on_return_set;
    BOOLEAN break_on_apiname_set;

    int dumptype0;
    int trace_all;
    int step_out;
    int file_offsets;
    int divert_debugger_log;
    char *trace_into_api[EXCLUSION_MAX];
#endif
};

extern struct _g_config g_config;

int read_config(void);

#endif
