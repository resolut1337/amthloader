#pragma once
#include <Windows.h>
#include <tchar.h>

BOOL SetHandleInformatiom_ProtectedHandle()
{
	HANDLE hMutex;

	hMutex = CreateMutex(NULL, FALSE, (_T("Random name")));

	SetHandleInformation(hMutex, HANDLE_FLAG_PROTECT_FROM_CLOSE, HANDLE_FLAG_PROTECT_FROM_CLOSE);

	__try {
		CloseHandle(hMutex);
	}

	__except (HANDLE_FLAG_PROTECT_FROM_CLOSE) {
		return TRUE;
	}

	return FALSE;
}