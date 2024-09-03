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
            case 6: LOQ_zero("script", "ssssss", "arg1", args[0], "arg2", args[1], \
						"arg3", args[2], "arg4", args[3], "arg5", args[4], "arg6", args[5]); break; \
            case 5: LOQ_zero("script", "sssss", "arg1", args[0], "arg2", args[1], \
						"arg3", args[2], "arg4", args[3], "arg5", args[4]); break; \
            case 4: LOQ_zero("script", "ssss", "arg1", args[0], "arg2", args[1], \
						"arg3", args[2], "arg4", args[3]); break; \
            case 3: LOQ_zero("script", "sss", "arg1", args[0], "arg2", args[1], \
						"arg3", args[2]); break; \
            case 2: LOQ_zero("script", "ss", "arg1", args[0], "arg2", args[1]); break; \
            case 1: LOQ_zero("script", "s", "arg1", args[0]); break; \
            default: break; \
        } \
        return ret; \
    }

void variant_to_string(VARIANT* var, char* buffer, size_t bufferSize) {
    if (var->vt & VT_BYREF) {
        switch (var->vt & ~VT_BYREF) {
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

HOOKVBS(CCur)
HOOKVBS(CInt)
HOOKVBS(CLng)
HOOKVBS(CBool)
HOOKVBS(CByte)
HOOKVBS(CDate)
HOOKVBS(CDbl)
HOOKVBS(CSng)
HOOKVBS(CStr)
HOOKVBS(Hex)
HOOKVBS(Oct)
HOOKVBS(VarType)
HOOKVBS(IsDate)
HOOKVBS(IsEmpty)
HOOKVBS(IsNull)
HOOKVBS(IsNumeric)
HOOKVBS(IsArray)
HOOKVBS(IsObject)
HOOKVBS(Atn)
HOOKVBS(Cos)
HOOKVBS(Sin)
HOOKVBS(Tan)
HOOKVBS(Exp)
HOOKVBS(Log)
HOOKVBS(Sqr)
HOOKVBS(Randomize)
HOOKVBS(Rnd)
HOOKVBS(Timer)
HOOKVBS(LBound)
HOOKVBS(UBound)
HOOKVBS(RGB)
HOOKVBS(Len)
HOOKVBS(LenB)
HOOKVBS(Left)
HOOKVBS(LeftB)
HOOKVBS(Right)
HOOKVBS(RightB)
HOOKVBS(Mid)
HOOKVBS(MidB)
HOOKVBS(StrComp)
HOOKVBS(LCase)
HOOKVBS(UCase)
HOOKVBS(LTrim)
HOOKVBS(RTrim)
HOOKVBS(Trim)
HOOKVBS(Space)
HOOKVBS(String)
HOOKVBS(InStr)
HOOKVBS(InStrB)
HOOKVBS(Escape)
HOOKVBS(Unescape)
HOOKVBS(AscB)
HOOKVBS(ChrB)
HOOKVBS(Asc)
HOOKVBS(Chr)
HOOKVBS(AscW)
HOOKVBS(ChrW)
HOOKVBS(Abs)
HOOKVBS(Fix)
HOOKVBS(Int)
HOOKVBS(Sgn)
HOOKVBS(Now)
HOOKVBS(Date)
HOOKVBS(Time)
HOOKVBS(Day)
HOOKVBS(Month)
HOOKVBS(Weekday)
HOOKVBS(Year)
HOOKVBS(Hour)
HOOKVBS(Minute)
HOOKVBS(Second)
HOOKVBS(DateValue)
HOOKVBS(TimeValue)
HOOKVBS(DateSerial)
HOOKVBS(TimeSerial)
HOOKVBS(InputBox)
HOOKVBS(MsgBox)
HOOKVBS(CreateObject)
HOOKVBS(GetObject)
HOOKVBS(DateAdd)
HOOKVBS(DateDiff)
HOOKVBS(DatePart)
HOOKVBS(TypeName)
HOOKVBS(Array)
HOOKVBS(Erase)
HOOKVBS(Filter)
HOOKVBS(Join)
HOOKVBS(Split)
HOOKVBS(Replace)
HOOKVBS(StrReverse)
HOOKVBS(InStrRev)
HOOKVBS(Eval)
HOOKVBS(Execute)
HOOKVBS(ExecuteGlobal)
HOOKVBS(GetRef)
HOOKVBS(SetLocale)
HOOKVBS(GetLocale)
HOOKVBS(GetUILanguage)
HOOKVBS(LoadPicture)
HOOKVBS(ScriptEngine)
HOOKVBS(ScriptEngineMajorVersion)
HOOKVBS(ScriptEngineMinorVersion)
HOOKVBS(ScriptEngineBuildVersion)
HOOKVBS(FormatNumber)
HOOKVBS(FormatCurrency)
HOOKVBS(FormatPercent)
HOOKVBS(FormatDateTime)
HOOKVBS(WeekdayName)
HOOKVBS(MonthName)
HOOKVBS(Round)
HOOKVBS(Print)
