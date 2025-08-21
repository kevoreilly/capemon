#include <stdio.h>
#include "ntapi.h"
#include <powerbase.h>
#include "hooking.h"
#include "log.h"
#include "CAPE\CAPE.h"

HOOKDEF(BOOL, WINAPI, GetPwrCapabilities,
	_Out_	PSYSTEM_POWER_CAPABILITIES lpspc
){
	BOOL ret = Old_GetPwrCapabilities(lpspc);
	(*lpspc).SystemS4 = 1;
	LOQ_bool("device", "iiii", "S1", lpspc->SystemS1, "S2", lpspc->SystemS2, "S3", lpspc->SystemS3, "S4", lpspc->SystemS4);
	return ret;
}