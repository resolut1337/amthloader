#pragma once
#include <Windows.h>

BOOL IsWoW64()
{
	typedef BOOL(WINAPI* LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
	LPFN_ISWOW64PROCESS fnIsWow64Process;

	BOOL bIsWow64 = FALSE;
	fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(GetModuleHandle(("kernel32.dll")), "IsWow64Process");

	if (fnIsWow64Process != NULL)
	{
		if (!fnIsWow64Process(GetCurrentProcess(), &bIsWow64))
		{
		}
	}

	return bIsWow64;
}

BOOL NtGlobalFlag( VOID )
{
	PDWORD pNtGlobalFlag = NULL, pNtGlobalFlagWoW64 = NULL;

	BYTE* _teb32 = (BYTE*)__readgsdword(0x18);
	DWORD _peb32 = *(DWORD*)(_teb32 + 0x30);
	pNtGlobalFlag = (PDWORD)(_peb32 + 0x68);

	if (IsWoW64())
	{

		BYTE* _teb64 = (BYTE*)__readgsdword(0x18) - 0x2000;
		DWORD64 _peb64 = *(DWORD64*)(_teb64 + 0x60);
		pNtGlobalFlagWoW64 = (PDWORD)(_peb64 + 0xBC);
	}

	BOOL normalDetected = pNtGlobalFlag && *pNtGlobalFlag & 0x00000070;
	BOOL wow64Detected = pNtGlobalFlagWoW64 && *pNtGlobalFlagWoW64 & 0x00000070;

	if (normalDetected || wow64Detected)
		return TRUE;
	else
		return FALSE;
}