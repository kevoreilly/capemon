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
	if (ret) { 
		// Most VM systems does not support either S0 or S3 sleep, which can be used to detect the presence of a VM.
		// S0, S4 and S5 being enabled is typical for a normal Modern Standby machine. 
		(*lpspc).AoAc = 1;
		(*lpspc).SystemS4 = 1;
		(*lpspc).SystemS5 = 1;
	}
	LOQ_bool("device", "");
	return ret;
}
