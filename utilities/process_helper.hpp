#pragma once
#include <windows.h>
#include <tlhelp32.h>

namespace process_helper
{
	extern void terminate_process(const char* filename);
	extern bool check_process_run(const char* const processName);
}