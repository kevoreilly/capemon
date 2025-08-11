#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>

BOOL check_ntyieldexecution_switchtothread()
{
    BYTE ucCounter = 1;
    for (int i = 0; i < 8; i++)
    {
        Sleep(0x0F);
        ucCounter <<= (1 - SwitchToThread());
    }

    return !(ucCounter == 0);
}

BOOL check_hardwarebreakpoint()
{
    CONTEXT ctx;
    ZeroMemory(&ctx, sizeof(CONTEXT)); 
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS; 

    if(!GetThreadContext(GetCurrentThread(), &ctx))
        return TRUE;

    return !(ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3);
}

BOOL check_closehandle()
{
    __try
    {
        CloseHandle((HANDLE)0xDEADBEEF);
        return TRUE;
    }
    __except (EXCEPTION_INVALID_HANDLE == GetExceptionCode()
                ? EXCEPTION_EXECUTE_HANDLER 
                : EXCEPTION_CONTINUE_SEARCH)
    {
        return FALSE;
    }
}

int main(int argc, char **argv)
{
    BOOL close_handle_result;
    BOOL hardware_breakpoint_result;
    BOOL ntyieldexecution_result;
    close_handle_result = check_closehandle();
    hardware_breakpoint_result = check_hardwarebreakpoint();
    ntyieldexecution_result = check_ntyieldexecution_switchtothread();
    FILE *fptr;
    fptr = fopen("test_result.txt","w");
    if(fptr)
    {
        fprintf(fptr," Close handle test: %s\n Hardware breakpoint test: %s\n NTYieldExecution test: %s\n",
        close_handle_result ? "true": "false",
        hardware_breakpoint_result ? "true": "false",
        ntyieldexecution_result ? "true": "false");
    }
    fclose(fptr);
}