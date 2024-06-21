/*
CAPE - Config And Payload Extraction
Copyright(C) 2022 kevoreilly@gmail.com

This program is free software : you can redistribute it and / or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.If not, see <http://www.gnu.org/licenses/>.

This module is derived from Microsoft's IAntimalwareProvider interface sample 'AmsiProvider'.

https://github.com/microsoft/Windows-classic-samples/tree/main/Samples/AmsiProvider
*/
#pragma once

#include <windows.h>
#include <strsafe.h>
#include <amsi.h>
// This is needed to allow the monitor to still run on Win7
#undef NTDDI_VERSION
#define NTDDI_VERSION NTDDI_WIN7
#include <wrl/module.h>
#undef NTDDI_VERSION
#define NTDDI_VERSION WDK_NTDDI_VERSION
#include <string>
#include <chrono>
#include <shlwapi.h>

// From CAPE.h
#define AMSIBUFFER 0x6a
#define AMSISTREAM 0x6b

using namespace Microsoft::WRL;
using namespace std;

extern "C" void DebugOutput(_In_ LPCTSTR lpOutputString, ...);
extern "C" void ErrorOutput(_In_ LPCTSTR lpOutputString, ...);
extern "C" int DumpMemoryRaw(PVOID Buffer, SIZE_T Size);
extern "C" BOOL SetCapeMetaData(DWORD DumpType, DWORD TargetPid, HANDLE hTargetProcess, PVOID Address);

HMODULE g_currentModule;

STDAPI DllGetClassObject(_In_ REFCLSID rclsid, _In_ REFIID riid, _Outptr_ LPVOID FAR* ppv)
{
    return Module<InProc>::GetModule().GetClassObject(rclsid, riid, ppv);
}

class
	DECLSPEC_UUID("00000000-0000-0000-0000-000000000000")
    AmsiDumper : public RuntimeClass<RuntimeClassFlags<ClassicCom>, IAntimalwareProvider, FtmBase>
{
public:
    IFACEMETHOD(Scan)(_In_ IAmsiStream* stream, _Out_ AMSI_RESULT* result) override;
    IFACEMETHOD_(void, CloseSession)(_In_ ULONGLONG session) override;
    IFACEMETHOD(DisplayName)(_Outptr_ LPWSTR* displayName) override;
};

template<typename T>
T GetFixedSizeAttribute(_In_ IAmsiStream* stream, _In_ AMSI_ATTRIBUTE attribute)
{
    T result;
    ULONG actualSize;
    if (SUCCEEDED(stream->GetAttribute(attribute, sizeof(T), reinterpret_cast<PBYTE>(&result), &actualSize)) && actualSize == sizeof(T))
        return result;
    return T();
}

HRESULT AmsiDumper::Scan(_In_ IAmsiStream* stream, _Out_ AMSI_RESULT* result)
{
    auto session = GetFixedSizeAttribute<ULONGLONG>(stream, AMSI_ATTRIBUTE_SESSION);
    auto contentSize = GetFixedSizeAttribute<ULONGLONG>(stream, AMSI_ATTRIBUTE_CONTENT_SIZE);
    auto contentAddress = GetFixedSizeAttribute<PBYTE>(stream, AMSI_ATTRIBUTE_CONTENT_ADDRESS);

    if (contentAddress)
    {
		DebugOutput("AmsiDumper: Dumping AMSI buffer at 0x%p, size 0x%x\n", contentAddress, contentSize);
		SetCapeMetaData(AMSIBUFFER, NULL, NULL, NULL);
		DumpMemoryRaw(contentAddress, (SIZE_T)contentSize);
    }
    else if (contentSize)
    {
        BYTE chunk[1024];
        ULONG readSize;
		ULONGLONG position;
		PBYTE streamCopy = (PBYTE)malloc(contentSize);

		if (streamCopy == NULL)
		{
			DebugOutput("AmsiDumper: Failed to allocate 0x%x bytes for stream copy.\n", contentSize);
			goto end;
		}

		for (position = 0; position < contentSize; position += readSize)
		{
			HRESULT hr = stream->Read(position, sizeof(chunk), chunk, &readSize);
			if (SUCCEEDED(hr))
				memcpy(streamCopy + position, chunk, readSize);
			else
			{
				DebugOutput("AmsiDumper: Failed to copy stream.\n");
				goto end;
			}
		}

		if (position)
		{

			DebugOutput("AmsiDumper: Dumping AMSI stream at 0x%p, size 0x%x", streamCopy, contentSize);
			SetCapeMetaData(AMSISTREAM, NULL, NULL, NULL);
			DumpMemoryRaw(streamCopy, contentSize);
			free(streamCopy);
		}
    }
	else
		DebugOutput("AmsiDumper: AMSI scan request unhandled; contentAddress & contentSize both zero.\n");
end:
    *result = AMSI_RESULT_NOT_DETECTED;
    return S_OK;
}

void AmsiDumper::CloseSession(_In_ ULONGLONG session)
{
}

HRESULT AmsiDumper::DisplayName(_Outptr_ LPWSTR *displayName)
{
    return S_OK;
}

CoCreatableClass(AmsiDumper);

HRESULT SetKeyStringValue(_In_ HKEY key, _In_opt_ PCWSTR subkey, _In_opt_ PCWSTR valueName, _In_ PCWSTR stringValue)
{
    LONG status = RegSetKeyValueW(key, subkey, valueName, REG_SZ, stringValue, (DWORD)(wcslen(stringValue) + 1) * sizeof(wchar_t));
	if (status)
		SetLastError(status);	// for ErrorOutput()
	return HRESULT_FROM_WIN32(status);
}

extern "C" void AmsiDumperInit(HMODULE module)
{
    wchar_t modulePath[MAX_PATH];
	g_currentModule = module;

    if (GetModuleFileNameW(g_currentModule, modulePath, ARRAYSIZE(modulePath)) >= ARRAYSIZE(modulePath))
		goto error;

    // Create a standard COM registration for our CLSID.
    // The class must be registered as "Both" threading model and support multithreaded access.
    wchar_t clsidString[40];
    if (StringFromGUID2(__uuidof(AmsiDumper), clsidString, ARRAYSIZE(clsidString)) == 0)
		goto error;

    wchar_t keyPath[200];
    HRESULT hr = StringCchPrintfW(keyPath, ARRAYSIZE(keyPath), L"Software\\Classes\\CLSID\\%ls", clsidString);
    if (FAILED(hr))
		goto error;

    hr = SetKeyStringValue(HKEY_LOCAL_MACHINE, keyPath, nullptr, L"AmsiDumper");
    if (FAILED(hr))
		goto error;

    hr = StringCchPrintfW(keyPath, ARRAYSIZE(keyPath), L"Software\\Classes\\CLSID\\%ls\\InProcServer32", clsidString);
    if (FAILED(hr))
		goto error;

    hr = SetKeyStringValue(HKEY_LOCAL_MACHINE, keyPath, nullptr, modulePath);
    if (FAILED(hr))
		goto error;

    hr = SetKeyStringValue(HKEY_LOCAL_MACHINE, keyPath, L"ThreadingModel", L"Both");
    if (FAILED(hr))
		goto error;

    // Register this CLSID as an anti-malware provider.
    hr = StringCchPrintfW(keyPath, ARRAYSIZE(keyPath), L"Software\\Microsoft\\AMSI\\Providers\\%ls", clsidString);
    if (FAILED(hr))
		goto error;

    hr = SetKeyStringValue(HKEY_LOCAL_MACHINE, keyPath, nullptr, L"AmsiDumper");
    if (FAILED(hr))
    	goto error;

    DebugOutput("AmsiDumper initialised.\n");
	return;
error:
	ErrorOutput("AmsiDumper: Is CAPE agent running elevated? Initialisation failed");
	return;
}
