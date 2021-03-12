#include <Windows.h>


#pragma once

#include <Windows.h>
#include <vector>
#include <tchar.h>

class HardDisk {
public:
	WCHAR shortName[3];
	WCHAR longName[MAX_PATH];
	size_t longNameLength;
};

class DeviceNameResolver
{
public:
	DeviceNameResolver();
	~DeviceNameResolver();
	bool resolveDeviceLongNameToShort(const WCHAR * sourcePath, WCHAR * targetPath);
private:
	std::vector<HardDisk> deviceNameList;

	void initDeviceNameList();
	void fixVirtualDevices();
};

