#include <stdio.h>
#include "log.h"

#define HOOKVBS(apiname) \
    int (WINAPI *Old_##apiname)(VARIANT* a1, int a2, VARIANT* a3); \
    int WINAPI New_##apiname(VARIANT* a1, int a2, VARIANT* a3) { \
        int ret = 0; \
        ret = Old_##apiname(a1, a2, a3); \
        char args[6][256] = {0}; \
        for (int i = 0; i < a2 && i < 6; i++) { \
            variant_to_string(&a3[i], args[i], sizeof(args[i])); \
        } \
        switch(a2) { \
            case 6: LOQ_hresult("script", "ssssss", "arg1", args[0], "arg2", args[1], \
						"arg3", args[2], "arg4", args[3], "arg5", args[4], "arg6", args[5]); break; \
            case 5: LOQ_hresult("script", "sssss", "arg1", args[0], "arg2", args[1], \
						"arg3", args[2], "arg4", args[3], "arg5", args[4]); break; \
            case 4: LOQ_hresult("script", "ssss", "arg1", args[0], "arg2", args[1], \
						"arg3", args[2], "arg4", args[3]); break; \
            case 3: LOQ_hresult("script", "sss", "arg1", args[0], "arg2", args[1], \
						"arg3", args[2]); break; \
            case 2: LOQ_hresult("script", "ss", "arg1", args[0], "arg2", args[1]); break; \
            case 1: LOQ_hresult("script", "s", "arg1", args[0]); break; \
            default: break; \
        } \
        return ret; \
    }

void variant_to_string(VARIANT* var, char* buffer, size_t bufferSize) {
    if (var->vt & VT_BYREF) {
        switch (var->vt & ~VT_BYREF) {
            case 74:
                variant_to_string(var->pvRecord, buffer, bufferSize);
                break;
            case VT_VARIANT:
                variant_to_string(var->pvarVal, buffer, bufferSize);
                break;
            case VT_BSTR:
                snprintf(buffer, bufferSize, "%ws", *var->pbstrVal);
                break;
            case VT_I4:
                snprintf(buffer, bufferSize, "%d", *var->plVal);
                break;
            case VT_R8:
                snprintf(buffer, bufferSize, "%lf", *var->pdblVal);
                break;
            case VT_BOOL:
                snprintf(buffer, bufferSize, "%s", *var->pboolVal ? "TRUE" : "FALSE");
                break;
            case VT_DATE:
                snprintf(buffer, bufferSize, "%lf", *var->pdate);
                break;
            case VT_UI1:
                snprintf(buffer, bufferSize, "%u", *var->pbVal);
                break;
            case VT_I2:
                snprintf(buffer, bufferSize, "%d", *var->piVal);
                break;
            case VT_UI2:
                snprintf(buffer, bufferSize, "%u", *var->puiVal);
                break;
            case VT_UI4:
                snprintf(buffer, bufferSize, "%u", *var->pulVal);
                break;
            case VT_INT:
                snprintf(buffer, bufferSize, "%d", *var->pintVal);
                break;
            case VT_UINT:
                snprintf(buffer, bufferSize, "%u", *var->puintVal);
                break;
            case VT_ERROR:
                snprintf(buffer, bufferSize, "Error: 0x%lx", *var->pscode);
                break;
            case VT_ARRAY:
                snprintf(buffer, bufferSize, "Array (byref), type: 0x%x", var->vt & ~VT_BYREF);
                break;
            default:
                snprintf(buffer, bufferSize, "Unhandled byref type: 0x%x", var->vt);
                break;
        }
    } else {
        switch (var->vt) {
            case 74:
                variant_to_string(var->pvRecord, buffer, bufferSize);
                break;
            case VT_VARIANT:
                variant_to_string(var->pvarVal, buffer, bufferSize);
                break;
            case VT_BSTR:
                snprintf(buffer, bufferSize, "%ws", var->bstrVal);
                break;
            case VT_I4:
                snprintf(buffer, bufferSize, "%d", var->lVal);
                break;
            case VT_R8:
                snprintf(buffer, bufferSize, "%lf", var->dblVal);
                break;
            case VT_BOOL:
                snprintf(buffer, bufferSize, "%s", var->boolVal ? "TRUE" : "FALSE");
                break;
            case VT_DATE:
                snprintf(buffer, bufferSize, "%lf", var->date);
                break;
            case VT_UI1:
                snprintf(buffer, bufferSize, "%u", var->bVal);
                break;
            case VT_I2:
                snprintf(buffer, bufferSize, "%d", var->iVal);
                break;
            case VT_UI2:
                snprintf(buffer, bufferSize, "%u", var->uiVal);
                break;
            case VT_UI4:
                snprintf(buffer, bufferSize, "%u", var->ulVal);
                break;
            case VT_INT:
                snprintf(buffer, bufferSize, "%d", var->intVal);
                break;
            case VT_UINT:
                snprintf(buffer, bufferSize, "%u", var->uintVal);
                break;
            case VT_ERROR:
                snprintf(buffer, bufferSize, "Error: 0x%lx", var->scode);
                break;
            case VT_ARRAY:
                snprintf(buffer, bufferSize, "Array, type: 0x%x", var->vt);
                break;
            default:
                snprintf(buffer, bufferSize, "Unhandled type: 0x%x", var->vt);
                break;
        }
    }
}

HOOKVBS(VbsCCur)
HOOKVBS(VbsCInt)
HOOKVBS(VbsCLng)
HOOKVBS(VbsCBool)
HOOKVBS(VbsCByte)
HOOKVBS(VbsCDate)
HOOKVBS(VbsCDbl)
HOOKVBS(VbsCSng)
HOOKVBS(VbsCStr)
HOOKVBS(VbsHex)
HOOKVBS(VbsOct)
HOOKVBS(VbsVarType)
HOOKVBS(VbsIsDate)
HOOKVBS(VbsIsEmpty)
HOOKVBS(VbsIsNull)
HOOKVBS(VbsIsNumeric)
HOOKVBS(VbsIsArray)
HOOKVBS(VbsIsObject)
HOOKVBS(VbsAtn)
HOOKVBS(VbsCos)
HOOKVBS(VbsSin)
HOOKVBS(VbsTan)
HOOKVBS(VbsExp)
HOOKVBS(VbsLog)
HOOKVBS(VbsSqr)
HOOKVBS(VbsRandomize)
HOOKVBS(VbsRnd)
HOOKVBS(VbsTimer)
HOOKVBS(VbsLBound)
HOOKVBS(VbsUBound)
HOOKVBS(VbsRGB)
HOOKVBS(VbsLen)
HOOKVBS(VbsLenB)
HOOKVBS(VbsLeft)
HOOKVBS(VbsLeftB)
HOOKVBS(VbsRight)
HOOKVBS(VbsRightB)
HOOKVBS(VbsMid)
HOOKVBS(VbsMidB)
HOOKVBS(VbsStrComp)
HOOKVBS(VbsLCase)
HOOKVBS(VbsUCase)
HOOKVBS(VbsLTrim)
HOOKVBS(VbsRTrim)
HOOKVBS(VbsTrim)
HOOKVBS(VbsSpace)
HOOKVBS(VbsString)
HOOKVBS(VbsInStr)
HOOKVBS(VbsInStrB)
HOOKVBS(VbsEscape)
HOOKVBS(VbsUnescape)
HOOKVBS(VbsAscB)
HOOKVBS(VbsChrB)
HOOKVBS(VbsAsc)
HOOKVBS(VbsChr)
HOOKVBS(VbsAscW)
HOOKVBS(VbsChrW)
HOOKVBS(VbsAbs)
HOOKVBS(VbsFix)
HOOKVBS(VbsInt)
HOOKVBS(VbsSgn)
HOOKVBS(VbsNow)
HOOKVBS(VbsDate)
HOOKVBS(VbsTime)
HOOKVBS(VbsDay)
HOOKVBS(VbsMonth)
HOOKVBS(VbsWeekday)
HOOKVBS(VbsYear)
HOOKVBS(VbsHour)
HOOKVBS(VbsMinute)
HOOKVBS(VbsSecond)
HOOKVBS(VbsDateValue)
HOOKVBS(VbsTimeValue)
HOOKVBS(VbsDateSerial)
HOOKVBS(VbsTimeSerial)
HOOKVBS(VbsInputBox)
HOOKVBS(VbsMsgBox)
HOOKVBS(VbsCreateObject)
HOOKVBS(VbsGetObject)
HOOKVBS(VbsDateAdd)
HOOKVBS(VbsDateDiff)
HOOKVBS(VbsDatePart)
HOOKVBS(VbsTypeName)
HOOKVBS(VbsArray)
HOOKVBS(VbsErase)
HOOKVBS(VbsFilter)
HOOKVBS(VbsJoin)
HOOKVBS(VbsSplit)
HOOKVBS(VbsReplace)
HOOKVBS(VbsStrReverse)
HOOKVBS(VbsInStrRev)
HOOKVBS(VbsEval)
HOOKVBS(VbsExecute)
HOOKVBS(VbsExecuteGlobal)
HOOKVBS(VbsGetRef)
HOOKVBS(VbsSetLocale)
HOOKVBS(VbsGetLocale)
HOOKVBS(VbsGetUILanguage)
HOOKVBS(VbsLoadPicture)
HOOKVBS(VbsScriptEngine)
HOOKVBS(VbsScriptEngineMajorVersion)
HOOKVBS(VbsScriptEngineMinorVersion)
HOOKVBS(VbsScriptEngineBuildVersion)
HOOKVBS(VbsFormatNumber)
HOOKVBS(VbsFormatCurrency)
HOOKVBS(VbsFormatPercent)
HOOKVBS(VbsFormatDateTime)
HOOKVBS(VbsWeekdayName)
HOOKVBS(VbsMonthName)
HOOKVBS(VbsRound)
HOOKVBS(VbsPrint)
