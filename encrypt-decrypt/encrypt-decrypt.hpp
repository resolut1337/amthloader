#pragma once
#include <windows.h>
#include <D:\sourca\Loader\libs\CryptoPP\aes.h>
#include <D:\sourca\Loader\libs\CryptoPP\modes.h>
#include <D:\sourca\Loader\libs\CryptoPP\base64.h>

#pragma comment(lib, "D:/sourca/Loader/libs/cryptlib.lib")

namespace aes 
{
	extern __forceinline std::string encrypt(const std::string& str, const std::string& cipher_key, const std::string& iv_key);
	extern __forceinline std::string decrypt(const std::string& str, const std::string& cipher_key, const std::string& iv_key);
}

namespace base_64
{
	extern __forceinline std::string encrypt(unsigned char const* bytes_to_encode, size_t in_len);
	extern __forceinline std::string decrypt(std::string const& str);
	inline bool is_base64(unsigned char c)
	{
		return (isalnum(c) || (c == '+') || (c == '/'));
	}
}

