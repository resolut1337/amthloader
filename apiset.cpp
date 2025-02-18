class apiset {
	std::unordered_map<std::string, std::string> m_apimap;
public:
	apiset();

	bool find(std::string& mod) {
		auto it = std::find_if(m_apimap.begin(), m_apimap.end(), [&](const std::pair<std::string, std::string>& pair) {
			return mod.find(pair.first) != std::string::npos;
			});

		if (it != m_apimap.end()) {
			mod = it->second;
			return true;
		}
		return false;
	}

	auto& map() { return m_apimap; }
};

#include "includes.h"
#include "util.h"
#include "io.h"
apiset g_apiset;
#include "apiset.h"
apiset::apiset() {
	auto map = *reinterpret_cast<native::API_SET_NAMESPACE_ARRAY**>(uintptr_t(util::peb()) + 0x68);
	for (int i = 0; i < map->Count; ++i) {
		std::wstring wapi_name(255, 0);
		std::wstring wapi_host(255, 0);

		auto entry = reinterpret_cast<native::API_SET_NAMESPACE_ENTRY*>(uintptr_t(map) + map->End + i * sizeof(native::API_SET_NAMESPACE_ENTRY));
		auto array = reinterpret_cast<native::API_SET_VALUE_ARRAY*>(uintptr_t(map) + map->Start + entry->Size * sizeof(native::API_SET_VALUE_ARRAY));

		auto byte_map = reinterpret_cast<uint8_t*>(map);
		std::memcpy(&wapi_name[0], &byte_map[array->NameOffset], array->NameLength);

		auto host = reinterpret_cast<native::API_SET_VALUE_ENTRY*>(&byte_map[array->DataOffset]);

		std::memcpy(&wapi_host[0], &byte_map[host->ValueOffset], host->ValueLength);

		wapi_name.assign(wapi_name.data());
		wapi_host.assign(wapi_host.data());

		auto api_name = util::wide_to_multibyte(wapi_name);
		auto api_host = util::wide_to_multibyte(wapi_host);

		m_apimap[api_name] = api_host;
	}
}