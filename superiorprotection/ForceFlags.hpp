#pragma once
#include <Windows.h>
//#include "../../Helpers/VersionHelpers.hpp"

BOOL HeapForceFlags()
{
	PUINT32 pProcessHeap, pHeapForceFlags = NULL;
	if (IsWindowsVistaOrGreater())
	{
		pProcessHeap = (PUINT32)(__readgsdword(0x30) + 0x18);
		pHeapForceFlags = (PUINT32)(*pProcessHeap + 0x44);

	}

	else {
		pProcessHeap = (PUINT32)(__readgsdword(0x30) + 0x18);
		pHeapForceFlags = (PUINT32)(*pProcessHeap + 0x10);
	}

	if (*pHeapForceFlags > 0)
		return TRUE;
	else
		return FALSE;
}