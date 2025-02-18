#pragma once

#include "driver.h"
#include "xora.h"
#include <ShlObj_core.h>

#define patch_shell   xor_w(L"\\SoftwareDistribution\\Download\\")



wstring random_string_w()
{
	srand((unsigned int)time((time_t*)0));
	wstring str = xor_w(L"QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm1234567890");
	wstring newstr;
	int pos;
	while (newstr.size() != 5)
	{
		pos = ((rand() % (str.size() + 1)));
		newstr += str.substr(pos, 1);
	}
	return newstr;
}

wstring get_parent(const wstring& path)
{
	if (path.empty())
		return path;

	auto idx = path.rfind(L'\\');
	if (idx == path.npos)
		idx = path.rfind(L'/');

	if (idx != path.npos)
		return path.substr(0, idx);
	else
		return path;
}

wstring get_exe_directory()
{
	wchar_t imgName[MAX_PATH] = { 0 };
	DWORD len = ARRAYSIZE(imgName);
	QueryFullProcessImageNameW(GetCurrentProcess(), 0, imgName, &len);
	wstring sz_dir = (wstring(get_parent(imgName)) + xor_w(L"\\"));
	return sz_dir;
}
const wchar_t* GetWC(const char* c)
{
	const size_t cSize = strlen(c) + 1;
	wchar_t* wc = new wchar_t[cSize];
	mbstowcs(wc, c, cSize);
	return wc;
}
wstring get_files_directory()
{
	/*static TCHAR pathqw[MAX_PATH];
	std::string savedCreditsPathqw;
	SHGetFolderPath(NULL, CSIDL_APPDATA, NULL, NULL, pathqw);
	savedCreditsPathqw = std::string(pathqw) + xorstr_("\\AMTH.CSGO\\");
	return GetWC(savedCreditsPathqw.c_str());*/

	WCHAR system_dir[256];
	GetWindowsDirectoryW(system_dir, 256);
	wstring sz_dir = (wstring(system_dir) + xor_w(L"\\SoftwareDistribution\\Download\\"));
	return sz_dir;
}

wstring get_random_file_name_directory(wstring type_file)
{
	//wstring sz_file = random_string_w() + type_file;
	wstring sz_file = get_files_directory() + random_string_w() + type_file;
	return sz_file;
}

void run_us_admin(std::wstring sz_exe, bool show)
{
	ShellExecuteW(NULL, xor_w(L"runas"), sz_exe.c_str(), NULL, NULL, show);
}

void run_us_admin_and_params(wstring sz_exe, wstring sz_params, bool show)
{
	ShellExecuteW(NULL, xor_w(L"runas"), sz_exe.c_str(), sz_params.c_str(), NULL, show);
}

bool drop_mapper(wstring path)
{
	HANDLE h_file;
	BOOLEAN b_status = FALSE;
	DWORD byte = 0;

	h_file = CreateFileW(path.c_str(), GENERIC_ALL, NULL, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
	if (GetLastError() == ERROR_FILE_EXISTS)
		return true;

	if (h_file == INVALID_HANDLE_VALUE)
		return false;

	b_status = WriteFile(h_file, shell_mapper, sizeof(shell_mapper), &byte, nullptr);
	CloseHandle(h_file);

	if (!b_status)
		return false;

	return true;
}

bool drop_driver(wstring path)
{
	HANDLE h_file;
	BOOLEAN b_status = FALSE;
	DWORD byte = 0;

	h_file = CreateFileW(path.c_str(), GENERIC_ALL, NULL, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
	if (GetLastError() == ERROR_FILE_EXISTS)
		return true;

	if (h_file == INVALID_HANDLE_VALUE)
		return false;

	b_status = WriteFile(h_file, shell_driver, sizeof(shell_driver), &byte, nullptr);
	CloseHandle(h_file);

	if (!b_status)
		return false;

	return true;
}

wstring get_files_path()
{
	WCHAR system_dir[256];
	GetWindowsDirectoryW(system_dir, 256);
	return (wstring(system_dir) + patch_shell);
}
bool injecttruehihihaharagemp = false;
void map_driver()
{

	/*static TCHAR pathsa[MAX_PATH];
	std::string savedCreditsPath;
	SHGetFolderPath(NULL, CSIDL_APPDATA, NULL, NULL, pathsa);
	savedCreditsPath = std::string(pathsa) + xorstr_("\\AMTH.CSGO\\");
	CreateDirectory(savedCreditsPath.c_str(), 0);
	std::wstring wstr(savedCreditsPath.begin(), savedCreditsPath.end());*/

	/*wstring sz_driver = wstr.c_str() + random_string_w() + (L".sys");
	wstring sz_mapper = wstr.c_str() + random_string_w() + (L".exe");*/


	wstring sz_driver = L"C:/" + random_string_w() + (L".sys");
	wstring sz_mapper = L"C:/" + random_string_w() + (L".exe");

	//wstring sz_params_map = xor_w(L"-map ") + sz_driver;
	wstring sz_params_map = sz_driver;


	DeleteFileW(sz_driver.c_str());
	DeleteFileW(sz_mapper.c_str());

	Sleep(500);

	drop_driver(sz_driver);
	drop_mapper(sz_mapper);

	run_us_admin_and_params(sz_mapper, sz_params_map, false);
	Sleep(1000);

	DeleteFileW(sz_driver.c_str());
	DeleteFileW(sz_mapper.c_str());

	injecttruehihihaharagemp = true;
}
