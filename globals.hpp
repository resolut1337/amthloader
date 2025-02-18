#pragma once

struct globals
{
	struct
	{
		std::string version;
		std::string status;

		std::string ip = xorstr_("amph.su"); //fe1zep48.beget.tech //fe1zepai.beget.tech

		struct
		{
			std::string cipher;
			std::string iv;
		} key;

	} server_side;

	struct
	{
		std::string version = xorstr_("1.4");//1.184

		struct
		{
			std::string name = utilities::get_random_string(16);
			float width = 690.f;
			float height = 430.f;
		} window_settings;		

		struct
		{
			std::string	filepathupdater = "C:/Games/Rust";
		//	std::string key;
			std::string key;
			//std::string hwid = utilities::get_hwid();

			std::string token;
			std::string structure_cheat;

		} data;

	} client_side;
};

extern globals g_globals;