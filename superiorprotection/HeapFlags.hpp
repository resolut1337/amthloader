#pragma once
#include <Windows.h>
#pragma once


BOOL HeapFlags()
{
	PUINT32 pProcessHeap, pHeapFlags = NULL;

	if (IsWindowsVistaOrGreater()) {
		pProcessHeap = (PUINT32)(__readgsdword(0x30) + 0x18);
		pHeapFlags = (PUINT32)(*pProcessHeap + 0x40);
	}

	else {
		pProcessHeap = (PUINT32)(__readgsdword(0x30) + 0x18);
		pHeapFlags = (PUINT32)(*pProcessHeap + 0x0C);
	}

	if (*pHeapFlags > 2)
		return TRUE;
	else
		return FALSE;
}
