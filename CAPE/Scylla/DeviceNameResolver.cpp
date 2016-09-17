
#include "DeviceNameResolver.h"
#include "NativeWinApi.h"

DeviceNameResolver::DeviceNameResolver()
{
    NativeWinApi::initialize();
	initDeviceNameList();
}

DeviceNameResolver::~DeviceNameResolver()
{
	deviceNameList.clear();
}

void DeviceNameResolver::initDeviceNameList()
{
	WCHAR shortName[3] = {0};
	WCHAR longName[MAX_PATH] = {0};
	HardDisk hardDisk;

	shortName[1] = TEXT(':');

	deviceNameList.reserve(3);

	for ( TCHAR shortD = TEXT('a'); shortD <= TEXT('z'); shortD++ )
	{
		shortName[0] = shortD;
		if (QueryDosDeviceW( shortName, longName, MAX_PATH ) > 0)
		{
			hardDisk.shortName[0] = _totupper(shortD);
			hardDisk.shortName[1] = TEXT(':');
			hardDisk.shortName[2] = 0;

			hardDisk.longNameLength = wcslen(longName);

			
			wcscpy_s(hardDisk.longName, longName);
			deviceNameList.push_back(hardDisk);
		}
	}

    fixVirtualDevices();
}

bool DeviceNameResolver::resolveDeviceLongNameToShort(const WCHAR * sourcePath, WCHAR * targetPath)
{
	for (unsigned int i = 0; i < deviceNameList.size(); i++)
	{
		if (!_wcsnicmp(deviceNameList[i].longName, sourcePath, deviceNameList[i].longNameLength) && sourcePath[deviceNameList[i].longNameLength] == TEXT('\\'))
		{
			wcscpy_s(targetPath, MAX_PATH, deviceNameList[i].shortName);
			wcscat_s(targetPath, MAX_PATH, sourcePath + deviceNameList[i].longNameLength);
			return true;
		}
	}

	return false;
}

void DeviceNameResolver::fixVirtualDevices()
{
    const USHORT BufferSize = MAX_PATH * 2 * sizeof(WCHAR);
    WCHAR longCopy[MAX_PATH] = {0};
    OBJECT_ATTRIBUTES oa = {0};
    UNICODE_STRING unicodeInput = {0};
    UNICODE_STRING unicodeOutput = {0};
    HANDLE hFile = 0;
    ULONG retLen = 0;
    HardDisk hardDisk;

    unicodeOutput.Buffer = (PWSTR)malloc(BufferSize);
    if (!unicodeOutput.Buffer)
        return;

    for (unsigned int i = 0; i < deviceNameList.size(); i++)
    {
        wcscpy_s(longCopy, deviceNameList[i].longName);

        NativeWinApi::RtlInitUnicodeString(&unicodeInput, longCopy);
        InitializeObjectAttributes(&oa, &unicodeInput, 0, 0, 0);

        if(NT_SUCCESS(NativeWinApi::NtOpenSymbolicLinkObject(&hFile, SYMBOLIC_LINK_QUERY, &oa)))
        {
            unicodeOutput.Length = BufferSize;
            unicodeOutput.MaximumLength = unicodeOutput.Length;
            ZeroMemory(unicodeOutput.Buffer, unicodeOutput.Length);

            if (NT_SUCCESS(NativeWinApi::NtQuerySymbolicLinkObject(hFile, &unicodeOutput, &retLen)))
            {
                hardDisk.longNameLength = wcslen(unicodeOutput.Buffer);
                wcscpy_s(hardDisk.shortName, deviceNameList[i].shortName);
                wcscpy_s(hardDisk.longName, unicodeOutput.Buffer);
                deviceNameList.push_back(hardDisk);
            }  

            NativeWinApi::NtClose(hFile);
        }
    }

    free(unicodeOutput.Buffer);
}

