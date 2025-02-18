#include "includes.h"
#include "util.h"
#include "syscalls.h"
#include "apiset.h"
#include <signal.h>
#include "debugsecurity.h"
#include <thread>
#include "apiset.cpp"
#include "security.h"
#include "client.hpp"
#include "native.h"
#pragma comment(lib,"ntdll.lib")
syscalls g_syscalls;


std::unordered_map<std::string, std::vector<char>> debugsecurity::parsed_images;
__forceinline bool stop()
{
	return raise(11);
}
__forceinline bool read_file(const std::string_view path, std::vector<char>& out)
{
	std::ifstream file(path.data(), std::ios::binary);
	if (!file.good())
	{
		//std::cout << "{} isnt valid." << path << std::endl;
		return false;
	}

	file.unsetf(std::ios::skipws);

	file.seekg(0, std::ios::end);
	const size_t size = file.tellg();
	file.seekg(0, std::ios::beg);

	out.resize(size);

	file.read(&out[0], size);

	file.close();

	return true;
}
__forceinline bool init()
{
	std::list<std::string> blacklist = { "ntdll.dll", "kernel32.dll" };

	std::unordered_map<std::string, peq::virtual_image> memory_modules;
	std::unordered_map<std::string, peq::image<true>> disk_modules;
	if (!get_all_modules(memory_modules))
	{
		//std::cout << "failed to get loaded modules" << std::endl;
		return false;
	}

	for (auto& [name, vi] : memory_modules) {
		auto it = std::find(blacklist.begin(), blacklist.end(), name);
		if (it == blacklist.end()) {
			continue;
		}

		std::vector<char> raw;
		char path[MAX_PATH];
		GetModuleFileNameA(GetModuleHandleA(name.c_str()), path, MAX_PATH);

		if (!read_file(path, raw))
		{
			//std::cout << "failed to read{}" << name << std::endl;
			continue;
		}

		disk_modules[name] = peq::image<true>(raw);
	}

	for (auto& [name, image] : disk_modules) {
		std::vector<char> mem;

		image.copy(mem);
		image.relocate(mem, uintptr_t(GetModuleHandleA(name.c_str())));

		for (auto& [mod, funcs] : image.imports()) {
			std::string mod_name{ mod };
			g_apiset.find(mod_name);

			for (auto& func : funcs) {
				*reinterpret_cast<uintptr_t*>(&mem[func.rva]) = uintptr_t(GetProcAddress(GetModuleHandleA(mod_name.c_str()), func.name.c_str()));
			}
		}

		debugsecurity::parsed_images[name] = mem;
	}

	disk_modules.clear();
	memory_modules.clear();

	return !debugsecurity::parsed_images.empty();
}
void debugsecurity::thread()
{
	if (!init())
	{
		//std::cout << "failed to init security thread.";
		stop();
	}

	while (true)
	{
		check();
		std::this_thread::sleep_for(std::chrono::milliseconds(500));
		/*std::this_thread::sleep_for(chrono::seconds(1));*/
	}
}

__forceinline bool debugsecurity::check()
{
	static auto peb = util::peb();
	auto being_debugged = static_cast<bool>(peb->BeingDebugged);
	if (being_debugged)
	{
		stop();
		return true;
	}


	static auto query_info = g_syscalls.get<native::NtQueryInformationProcess>("NtQueryInformationProcess");

	uint32_t debug_inherit = 0;
	auto status = query_info(INVALID_HANDLE_VALUE, native::ProcessDebugFlags, &debug_inherit, sizeof(debug_inherit), 0);
	if (!NT_SUCCESS(status))
	{
		stop();
		//std::cout << "failed to get local process debug flags, status {:#X}." << (status & 0xFFFFFFFF);
		return true;
	}

	if (debug_inherit == 0)
	{
		stop();
		return true;
	}

	uint64_t remote_debug = 0;
	status = query_info(INVALID_HANDLE_VALUE, native::ProcessDebugPort, &remote_debug, sizeof(remote_debug), 0);
	if (!NT_SUCCESS(status))
	{
		stop();
		//std::cout << "failed to get local process debug port, status {:#X}." << (status & 0xFFFFFFFF) << std::endl;
		return true;
	}

	if (remote_debug != 0)
	{
		stop();
		return true;
	}

	return false;
}







//syscalls g_syscalls;

syscalls::syscalls() {
	m_call_table = VirtualAlloc(0, 0x100000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	std::memset(m_call_table, 0x90, 0x100000);
}

syscalls::~syscalls() {
	VirtualFree(m_call_table, 0, MEM_RELEASE);
}

void syscalls::init()
{
	/*std::cout << "syscall: 0x" << uintptr_t(m_call_table) << std::endl;*/
	static auto nt = peq::ntdll();
	for (auto& exp : nt.exports())
	{
		auto addr = exp.second;

		uint16_t offset;
		auto idx = get_index(addr, offset);

		if (!idx) continue;

		m_indexes[exp.first] = std::make_pair(idx, offset);

		if (m_stub.empty()) {
			auto s = func_size(reinterpret_cast<uint8_t*>(addr));

			m_stub.resize(s);

			memcpy(&m_stub[0], reinterpret_cast<void*>(addr), s);
		}
	}

	for (auto& [name, pair] : m_indexes)
	{
		auto& [idx, offset] = pair;

		auto addr = uintptr_t(m_call_table) + (idx * m_stub.size());
		std::memcpy(reinterpret_cast<void*>(addr), m_stub.data(), m_stub.size());

		*reinterpret_cast<uint8_t*>(addr + m_stub.size() - 1) = 0xc3;
		*reinterpret_cast<uint16_t*>(addr + offset + 1) = idx;
	}
}

bool syscalls::valid(const uintptr_t addr, const size_t& size) {
	auto func = reinterpret_cast<uint8_t*>(addr);

	// mov r10, rcx
	uint32_t a = func[0] + func[1] + func[2];
	if (a != 0x1a8) {
		return false;
	}

	for (size_t i{}; i < size; i++)
	{
		auto op = func[i];
		auto next = func[i + 1];

		if (op == 0x0f && next == 0x05)
		{
			return true;
		}
	}

	return false;
}

uint16_t syscalls::get_index(const uintptr_t va, uint16_t& offset) {
	auto func = reinterpret_cast<uint8_t*>(va);
	auto size = func_size(reinterpret_cast<uint8_t*>(va));
	if (!valid(va, size)) {
		return 0;
	}

	for (size_t i{}; i < size; i++) {
		auto op = func[i];
		if (op == 0xb8) {
			offset = i;

			return *reinterpret_cast<uint16_t*>(va + i + 1);
		}
	}
	return 0;
}

size_t syscalls::func_size(const uint8_t* func) {
	for (size_t i = 0; i < 64; i++) {
		auto op = func[i];
		if (op == 0xc3 || op == 0xc2) {
			return i + 1;
		}
	}
	return 0;
}
