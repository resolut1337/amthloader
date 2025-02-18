#pragma once
#include <Windows.h>
#include <winternl.h>

BOOL IsDebuggerPresentPEB( VOID )
{
	PPEB m_pPeb = ( PPEB )__readgsdword( 0x30 );
	return m_pPeb->BeingDebugged == 1;
}