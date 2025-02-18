#pragma once
#include <Windows.h>
#include <tchar.h>

BOOL OutputDebugStringAPI()
{
	BOOL IsDbgPresent = FALSE;
	DWORD Val = 0x29A;

	if (IsWindowsXPOr2k())
	{
		SetLastError(Val);
		OutputDebugString(_T("random"));

		if (GetLastError() == Val)
			IsDbgPresent = TRUE;
	}

	return IsDbgPresent;
}
