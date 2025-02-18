#include "other_f.hpp"
void INTERNET_VALID() {
	auto accepted_request = DownloadString((string)xorstr_("https://amph.su/client/internet_.php"));
	if (!(accepted_request == "SUCCESS_INTERNET")) {
		li(MessageBoxA)(NULL, xorstr_("Connection Los"), xorstr_("Loader"), MB_ICONERROR);
		exit(-1);
	}
}
void security_thread() {
	if (!utilities::is_elevated())
	{
		li(MessageBoxA)(NULL, xorstr_("Run the loader as an administrator"), xorstr_("Loader"), MB_ICONERROR);
		exit(-1);
	}
	if (sec::TestSign())
	{
		li(MessageBoxA)(NULL, xorstr_("Your system under Test Signing mode, disable this, before launching loader."), utilities::get_random_string(16).c_str(), MB_SYSTEMMODAL | MB_OK);
		utils::shutdown();
	}
	INTERNET_VALID();

	std::thread m_thUserActivity(HandleUserActivity_thread);
	m_thUserActivity.detach();

	g_syscalls.init();

	std::thread sec_thread(debugsecurity::thread);
	sec_thread.detach();

	if (sec::IsDebuggersInstalledStart())
		sec::shutdown();
	
	std::thread third(sec::ST);
	third.detach();

	if (!uLoader::check_version()) {
		Update();
		RenameAndDestroy();
	}

	if (uLoader::globalbanshwid(xorstr_("0")) == 1)
	{
		sec::Logger(xorstr_("banned!!."), 2);
		exit(-1);
	}
}
void enable_console(bool s) {
	if (s) { AllocConsole(); freopen("conin$", "r", stdin);	freopen("conout$", "w", stdout);	freopen("conout$", "w", stderr); }
}
#pragma warning(disable : 2872)
#pragma warning(disable : 4996)
#include <sapi.h>
#include <sphelper.h>
bool proverka_number_3 = false;
static int tabs = 0;
void thread_auth() {
	if (!g_XenForo.Endpoint.Auth.setup(xorstr_("https://amph.su/index.php/api/auth"), xorstr_("ON2q0uoTkrSj8JYV7eRnx8Gy_29auPqN")))
	{
		MessageBox(NULL, xorstr_("Setup ERROR"), Globals::client_side.cheat.c_str(), MB_ICONERROR | MB_DEFBUTTON2);
		exit(-1);
	}
	if (!g_XenForo.Endpoint.Auth.request(Global::client.username, Global::client.password))
	{
		check = false;
		MessageBox(NULL, xorstr_("Username or password is incorrect"), Globals::client_side.cheat.c_str(), MB_ICONERROR | MB_DEFBUTTON2);	
		USERNAMEORPASSWORDERROR = true;
	}
	else {
		if (g_XenForo.Endpoint.Auth.example())
		{
			//Successfully authenticated user
			std::string savedCreditsPath;
			std::string output = DownloadString(g_XenForo.Endpoint.Auth.Vars.User.avatar_urls.m);
			if (output.empty())
			{
				savedCreditsPath = DownloadString((string)xorstr_("https://www.clipartmax.com/png/full/331-3319918_anonymous-person-transparent.png"));
				//li(URLDownloadToFileA)(nullptr, xorstr_("https://www.clipartmax.com/png/full/331-3319918_anonymous-person-transparent.png"), savedCreditsPath.c_str(), 0, nullptr);
			}
			else {
				//li(URLDownloadToFileA)(nullptr, g_XenForo.Endpoint.Auth.Vars.User.avatar_urls.m.c_str(), savedCreditsPath.c_str(), 0, nullptr);
				savedCreditsPath = DownloadString((string)(g_XenForo.Endpoint.Auth.Vars.User.avatar_urls.m));
			}
			IconAvatarInit(savedCreditsPath);


			int check_login_status = uLoader::checkloginmb();

			if (check_login_status == 6) {
				MessageBox(NULL, xorstr_("you're banned лох ебаный"), Globals::client_side.cheat.c_str(), MB_ICONERROR | MB_DEFBUTTON2);
				exit(-1);
			}
			if (check_login_status == 2) {
				MessageBox(NULL, xorstr_("HWID error"), Globals::client_side.cheat.c_str(), MB_ICONERROR);
				exit(-1);
			}
			if (check_login_status == 3) {
				MessageBox(NULL, xorstr_("Subscription ERROR"), Globals::client_side.cheat.c_str(), MB_ICONERROR | MB_DEFBUTTON2);
				exit(-1);
			}
			if (check_login_status == 4) {
				check = false;
				MessageBox(NULL, xorstr_("Invalid username"), Globals::client_side.cheat.c_str(), MB_ICONERROR | MB_DEFBUTTON2);
			}
			if (check_login_status == 5) {
				check = false;
				MessageBox(NULL, xorstr_("Invalid password"), Globals::client_side.cheat.c_str(), MB_ICONERROR | MB_DEFBUTTON2);
			}
			if (check_login_status == 1) {
				


				/*ISpVoice* pVoice = NULL;
				if (FAILED(::CoInitialize(NULL)))
					return;
				HRESULT hr = CoCreateInstance(CLSID_SpVoice, NULL, CLSCTX_ALL, IID_ISpVoice, (LPVOID*)&pVoice);
				if (SUCCEEDED(hr))
				{
					hr = pVoice->Speak(L"<voice required=\"Gender=Female\"/><rate absspeed=\"3\"/><volume level=\"90\"/><pitch middle=\"-500\"/>слава украине ", 0, NULL);
				
					pVoice->Release();
				}
				::CoUninitialize();*/





				//{ /// save username
				//	static TCHAR pathqwq[MAX_PATH];
				//	std::string savedCreditsPathqwq;
				//	SHGetFolderPath(NULL, CSIDL_APPDATA, NULL, NULL, pathqwq);
				//	savedCreditsPathqwq = std::string(pathqwq) + xorstr_("\\AMTH.CSGO\\username.bin");
				//	bool notifydone = false;
				//	if (rememberme)
				//	{
				//		std::ofstream out;
				//		out.open(savedCreditsPathqwq);
				//		out << username;
				//		out.close();
				//	}
				//}
				//{ /// save password
				//	static TCHAR pathqwq[MAX_PATH];
				//	std::string savedCreditsPathqwq;
				//	SHGetFolderPath(NULL, CSIDL_APPDATA, NULL, NULL, pathqwq);
				//	savedCreditsPathqwq = std::string(pathqwq) + xorstr_("\\AMTH.CSGO\\password.bin");
				//	bool notifydone = false;
				//	if (rememberme)
				//	{
				//		std::ofstream out;
				//		out.open(savedCreditsPathqwq);
				//		out << password;
				//		out.close();
				//	}
				//}
				получениедатыподписки = uLoader::получениеподписки();

				activation_success = true;
				logined = true;		
				tabs = 1;
				tab_opening = !tab_opening;

				
			}
		}
	}


	while (true) {

		switch_Adress_func::_queue->on_new_tick();


		std::this_thread::sleep_for(std::chrono::seconds(1));
	}


}



struct button_state
{
	ImVec4 background, text, button;
};


bool ImGui::ButtonExCustom(ImTextureID user_texture_id, const char* label, const char* subtime, const ImVec2& size_arg, ImGuiButtonFlags flags)
{
	ImGuiWindow* window = GetCurrentWindow();

	if (window->SkipItems) return false;

	ImGuiContext& g = *GImGui;
	const ImGuiStyle& style = g.Style;
	const ImGuiID id = window->GetID(label);
	const ImVec2 label_size = CalcTextSize(label, NULL, true), pos = window->DC.CursorPos;

	ImVec2 size = CalcItemSize(size_arg, label_size.x, label_size.y);

	const ImRect bb(pos, pos + size);

	ItemSize(size, 0.f);
	if (!ItemAdd(bb, id)) return false;

	bool hovered, held, pressed = ButtonBehavior(bb, id, &hovered, &held, flags);

	static std::map<ImGuiID, button_state> anim;
	auto it_anim = anim.find(id);

	if (it_anim == anim.end())
	{
		anim.insert({ id, button_state() });
		it_anim = anim.find(id);
	}

	it_anim->second.background = ImLerp(it_anim->second.background, IsItemActive() ? c::button::outline_background : c::button::background, g.IO.DeltaTime * 6.f);
	it_anim->second.text = ImLerp(it_anim->second.text, IsItemActive() ? ImVec4(c::menu_sett::menu_color_swither.Value.x, c::menu_sett::menu_color_swither.Value.y, c::menu_sett::menu_color_swither.Value.z, 255.f) : c::text::text, g.IO.DeltaTime * 6.f);

	//ImGui::GetWindowDrawList()->AddRectFilled(bb.Min, bb.Max, GetColorU32(it_anim->second.background), c::button::rounding);
	ImGui::GetWindowDrawList()->AddRect(bb.Min, bb.Max, GetColorU32(c::button::outline_background), c::button::rounding);
	ImGui::PushFont(font::tahoma_bold);
	ImGui::GetWindowDrawList()->AddText(ImVec2(bb.Min.x + (size_arg.x - CalcTextSize(label).x) / 2, bb.Max.y - CalcTextSize(label).y - (size.y - CalcTextSize(label).y) + 7), GetColorU32(it_anim->second.text), label);
	ImGui::PopFont();
	ImGui::GetWindowDrawList()->AddImage(user_texture_id, bb.Min + ImVec2(10, 27), bb.Max - ImVec2(10, 27), ImVec2(0, 0), ImVec2(1, 1), ImColor(255,255,255,255));



	


	ImGui::GetWindowDrawList()->AddText(ImVec2(bb.Min.x + (size_arg.x - CalcTextSize(subtime).x) / 2, bb.Max.y - CalcTextSize(label).y - (size.y - CalcTextSize(label).y) + 100), GetColorU32(it_anim->second.text), subtime);

	//ImGui::GetWindowDrawList()->AddText(ImVec2(bb.Min.x + (size_arg.x - CalcTextSize(subtime).x) / 2, bb.Max.y - CalcTextSize(subtime).y - (size.y - CalcTextSize(subtime).y) * 3), GetColorU32(it_anim->second.text), subtime);



	

	return pressed;
}

bool ImGui::ButtonCustom(ImTextureID user_texture_id, const char* label, const char* subtime, const ImVec2& size_arg)
{
	return ButtonExCustom(user_texture_id, label, subtime, size_arg, ImGuiButtonFlags_None);
}

#include"bytes_product.h"

bool proverka_2 = false;
bool proverka_spinera_injecta = false;
bool proverka_thread_rage_inj = false;

float test_x_1 = 2.06;
float test_x_2 = 150;
float test_y_1 = 170;
float test_y_2 = 100;

bool check_proerer_background = false;
std::string cs2_expired_sub;
std::string gta5_altv_expired_sub;
std::string gta5_ragemp_expired_sub;
bool xuixuiuiui = false;
std::string rust_alkad_expired_sub;

__forceinline int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPTSTR lpCmdLine, int nCmdShow)
{
	{
		static TCHAR pathsa[MAX_PATH];
		std::string savedCreditsPath;
		SHGetFolderPath(NULL, CSIDL_APPDATA, NULL, NULL, pathsa);
		savedCreditsPath = std::string(pathsa) + xorstr_("\\AMTH.CSGO\\");
		CreateDirectory(savedCreditsPath.c_str(), 0);

		enable_console(false);

		auto accepted_request = DownloadString((string)xorstr_("https://amph.su/client/auto_login.php?hwid=") + utilities::get_hwidqwe().c_str());
		if (!accepted_request.empty()) {
			rememberlogin.clear();
			std::istringstream iss(accepted_request);
			std::string item;
			while (iss >> item) {
				rememberlogin.push_back(item);
			}
			std::strcpy(username, rememberlogin[0].c_str());
			std::strcpy(password, rememberlogin[1].c_str());
		}
	}



	security_thread();

	if (uLoader::check_version())
	{
		std::thread banthread(BanThread);
		banthread.detach();

		//LPCTSTR lpzClass = utilities::get_random_string(15).c_str();
		LPCTSTR lpzClass = "AMPH.su";
		if (!RegMyWindowClass(hInstance, lpzClass)) 
			return 1;
		RECT screen_rect;
		GetWindowRect(GetDesktopWindow(), &screen_rect);
		int x = screen_rect.right / 2.f, y = screen_rect.bottom / 2.f;
		hWnd = CreateWindow(lpzClass, lpzClass, WS_POPUP, x, y, 400.f, 380.f, NULL, NULL, hInstance, NULL);
		if (!hWnd) return 2;

		if (!CreateDeviceD3D(hWnd))
		{
			CleanupDeviceD3D();
			::UnregisterClassW((LPCWSTR)lpzClass, hInstance);
			return 1;
		}

		::ShowWindow(hWnd, SW_SHOWDEFAULT);
		::UpdateWindow(hWnd);


		IMGUI_CHECKVERSION();
		ImGui::CreateContext();
		ImGuiIO& io = ImGui::GetIO(); (void)io;
		io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
		io.ConfigFlags |= ImGuiConfigFlags_NavEnableGamepad;
		init_styles(ImGui::GetStyle());
		ImFontConfig cfg;
		cfg.FontBuilderFlags = ImGuiFreeTypeBuilderFlags_ForceAutoHint | ImGuiFreeTypeBuilderFlags_LightHinting | ImGuiFreeTypeBuilderFlags_LoadColor;
		font::poppins_medium = io.Fonts->AddFontFromMemoryTTF(poppins_medium, sizeof(poppins_medium), 17.f, &cfg, io.Fonts->GetGlyphRangesCyrillic());
		font::poppins_medium_low = io.Fonts->AddFontFromMemoryTTF(poppins_medium, sizeof(poppins_medium), 15.f, &cfg, io.Fonts->GetGlyphRangesCyrillic());
		font::tab_icon = io.Fonts->AddFontFromMemoryTTF(tabs_icons, sizeof(tabs_icons), 24.f, &cfg, io.Fonts->GetGlyphRangesCyrillic());
		font::tahoma_bold = io.Fonts->AddFontFromMemoryTTF(tahoma_bold, sizeof(tahoma_bold), 17.f, &cfg, io.Fonts->GetGlyphRangesCyrillic());
		//font::tahoma_bold2 = io.Fonts->AddFontFromMemoryTTF(tahoma_bold, sizeof(tahoma_bold), 28.f, &cfg, io.Fonts->GetGlyphRangesCyrillic());
		font::tahoma_bold2 = io.Fonts->AddFontFromMemoryTTF(tahoma_bold, sizeof(tahoma_bold), 26.f, &cfg, io.Fonts->GetGlyphRangesCyrillic());
		font::chicons = io.Fonts->AddFontFromMemoryTTF(chicon, sizeof(chicon), 20.f, &cfg, io.Fonts->GetGlyphRangesCyrillic());
		if (image::bg == nullptr) D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, background_image, sizeof(background_image), &info, pump, &image::bg, 0);
		if (image::logo == nullptr) D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, logo, sizeof(logo), &info, pump, &image::logo, 0);
		if (image::logo_general == nullptr) D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, logo_general, sizeof(logo_general), &info, pump, &image::logo_general, 0);
		if (image::arrow == nullptr) D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, arrow, sizeof(arrow), &info, pump, &image::arrow, 0);
		if (image::bell_notify == nullptr) D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, bell_notify, sizeof(bell_notify), &info, pump, &image::bell_notify, 0);
		if (image::roll == nullptr) D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, iconmain, sizeof(iconmain), &info, pump, &image::roll, 0);
		if (image::rusifikacia == nullptr) D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, engbyte, sizeof(engbyte), &info, pump, &image::rusifikacia, 0);
		if (image::rusifikacia_ru == nullptr) D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, rubyte, sizeof(rubyte), &info, pump, &image::rusifikacia_ru, 0);
		if (image::discord_logo == nullptr) D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, discordlogoo, sizeof(discordlogoo), &info, pump, &image::discord_logo, 0);
		if (image::telegram_logo == nullptr) D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, telegramlogo, sizeof(telegramlogo), &info, pump, &image::telegram_logo, 0);
		if (image::vk_logo == nullptr) D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, vklogoo, sizeof(vklogoo), &info, pump, &image::vk_logo, 0);
		if (image::site_logo == nullptr) D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, sitelogoo, sizeof(sitelogoo), &info, pump, &image::site_logo, 0);
		if (image::exit_logo == nullptr) D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, icexittoapp48px1024, sizeof(icexittoapp48px1024), &info, pump, &image::exit_logo, 0);

		if (image::logo_cs == nullptr) D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, cs, sizeof(cs), &info, pump, &image::logo_cs, 0);
		if (image::logo_rust == nullptr) D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, rust, sizeof(rust), &info, pump, &image::logo_rust, 0);
		if (image::logo_gta == nullptr) D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, gta, sizeof(gta), &info, pump, &image::logo_gta, 0);

		if (image::krest == nullptr) D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, multiply, sizeof(multiply), &info, pump, &image::krest, 0);
		if (image::Injectong == nullptr) D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, Injectong, sizeof(Injectong), &info, pump, &image::Injectong, 0);

		

		ImGui_ImplWin32_Init(hWnd);
		ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);
		bool show_another_window = false;
		ImVec4 clear_color = ImVec4(0.0f, 0.0f, 0.0f, 1.0f);

		bool done = false;
		while (!done)
		{
			if (proverka_number_3) {
				std::thread third(thread_auth);
				third.detach();
				proverka_number_3 = false;
			}
			MSG msg;
			while (::PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE))
			{
				::TranslateMessage(&msg);
				::DispatchMessage(&msg);
				if (msg.message == WM_QUIT)
					done = true;
			}
			if (done)
				break;

			if (g_ResizeWidth != 0 && g_ResizeHeight != 0)
			{
				CleanupRenderTarget();
				g_pSwapChain->ResizeBuffers(0, g_ResizeWidth, g_ResizeHeight, DXGI_FORMAT_UNKNOWN, 0);
				g_ResizeWidth = g_ResizeHeight = 0;
				CreateRenderTarget();
			}
			tab_size = ImLerp(tab_size, tab_opening ? 150.f : 0.f, ImGui::GetIO().DeltaTime * 12.f);
			ImGui_ImplDX11_NewFrame();
			ImGui_ImplWin32_NewFrame();


			IMGUI_API bool			ListBoxConfigArray(const char* label, int* currIndex, std::vector<std::string>&values, int height = 9, bool custom_selectable = true);
			ImGui::NewFrame();
			{
				ImGuiStyle* s = &ImGui::GetStyle();
				s->WindowPadding = ImVec2(0, 0), s->WindowBorderSize = 0;
				s->ItemSpacing = ImVec2(20, 20);
				s->ScrollbarSize = 8.f;

				ImGui::SetNextWindowSize(ImVec2(c::bg::size) + ImVec2(tab_size, 0));
				ImGui::SetNextWindowPos({ 0,0 });
				ImGui::Begin(xorstr_("IMGUI"), nullptr, ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoResize);
				{
					
					Particles();

					const ImVec2 spacing = ImGui::GetStyle().ItemSpacing;
					const ImVec2& pos = ImGui::GetWindowPos();
					ImVec2 p = ImGui::GetWindowPos();
					RECT screen_rect;
					GetWindowRect(hWnd, &screen_rect);
					int x = screen_rect.right / 2.f, y = screen_rect.bottom / 2.f;
					if (logined) {
						if (!pidorrrr) {

							MoveWindow(hWnd, x, y, 400.f + 360.f, 370 , true);
							c::bg::size = ImVec2(400.f + 360.f, 370 );


							pidorrrr = true;
						}

					}
					else {
						//MoveWindow(hWnd, pos.x, pos.y, 400.f, 380, false);
					}

					ImDrawList* drawq = ImGui::GetWindowDrawList();
					static ImColor col = ImColor(23, 23, 23);
					static ImColor col2 = ImColor(23, 23, 23);
					drawq->AddRectFilled(p, p + ImVec2(560 + 285, 30), col);
					drawq->AddText(p + ImVec2(30, 8), ImColor(255, 255, 255, 255), xorstr_("AMPH.su"));
					ImGui::SetCursorPos(ImVec2(5, 5));
					if (ImGui::CustomButton(1, image::exit_logo, ImVec2(17, 17), ImVec2(0, 0), ImVec2(1, 1), ImGui::GetColorU32(ImVec4(255, 255, 255, 255))))
						exit(-1);

					
					if (tabs != 0) {
						ImGui::SetCursorPos(ImVec2(c::bg::size.x / 2.f, 5));
					}
					else {
						ImGui::SetCursorPos(ImVec2(186, 5));
					}
					if (ImGui::CustomButton(1, image::roll, ImVec2(20, 20), ImVec2(0, 0), ImVec2(1, 1), ImGui::GetColorU32(ImVec4(c::menu_sett::menu_color_swither.Value.x, c::menu_sett::menu_color_swither.Value.y, c::menu_sett::menu_color_swither.Value.z, 255.f)))) sosihui = !sosihui;
					ImGui::GetBackgroundDrawList()->AddRectFilled(pos, pos + ImVec2(c::bg::size) + ImVec2(tab_size, 0), ImGui::GetColorU32(c::bg::background), c::bg::rounding);
					ImGui::GetBackgroundDrawList()->AddRect(pos, pos + ImVec2(c::bg::size) + ImVec2(tab_size, 0), ImGui::GetColorU32(c::bg::outline_background), c::bg::rounding);
					//window->AddRectFilledMultiColor({ position.x,position.y }, { position + ImVec2(c::bg::size) + ImVec2(tab_size, 0) }, ImColor(0, 0, alpha), ImColor(0, 0, alpha), ImColor(c::menu_sett::menu_color_swither.Value.x, c::menu_sett::menu_color_swither.Value.y, c::menu_sett::menu_color_swither.Value.z, alpha), ImColor(c::menu_sett::menu_color_swither.Value.x, c::menu_sett::menu_color_swither.Value.y, c::menu_sett::menu_color_swither.Value.z, alpha)); //dark
					ImGui::GetBackgroundDrawList()->AddRectFilledMultiColor(pos, pos + ImVec2(c::bg::size) + ImVec2(tab_size, 0), ImColor(0, 0, 0), ImColor(0, 0, 0), ImColor(c::menu_sett::menu_color_swither.Value.x, c::menu_sett::menu_color_swither.Value.y, c::menu_sett::menu_color_swither.Value.z, 0.f), ImColor(c::menu_sett::menu_color_swither.Value.x, c::menu_sett::menu_color_swither.Value.y, c::menu_sett::menu_color_swither.Value.z, 0.f)); //dark

					ImGui::PushStyleColor(ImGuiCol_Text, ImGui::GetColorU32(c::accent_text_color));
					{
						if (tabs != 1) {
							if (tabs != 0) {
								ImGui::SetCursorPos(ImVec2(67 + tab_size, 5) + (s->ItemSpacing * 2));
								ImGuiContext& g = *GImGui;
								ImGuiWindow* parent_window = g.CurrentWindow;
								ImGui::GetWindowDrawList()->AddRectFilled(parent_window->DC.CursorPos, parent_window->DC.CursorPos + ImVec2((c::bg::size.x - s->ItemSpacing.x * 6.5), 60), ImGui::GetColorU32(c::child::background), c::child::rounding);
								ImGui::GetWindowDrawList()->AddRect(parent_window->DC.CursorPos, parent_window->DC.CursorPos + ImVec2((c::bg::size.x - s->ItemSpacing.x * 6.5), 60), ImGui::GetColorU32(c::child::outline_background), c::child::rounding);

								ImGui::SetCursorPos(ImVec2(80 + tab_size, +20) + (s->ItemSpacing * 2));
							}
							else {

								ImGui::SetCursorPos(ImVec2(tab_size, 5) + (s->ItemSpacing * 2));
								ImGuiContext& g = *GImGui;
								ImGuiWindow* parent_window = g.CurrentWindow;
								ImGui::GetWindowDrawList()->AddRectFilled(parent_window->DC.CursorPos, parent_window->DC.CursorPos + ImVec2((c::bg::size.x - s->ItemSpacing.x * 4), 60), ImGui::GetColorU32(c::child::background), c::child::rounding);
								ImGui::GetWindowDrawList()->AddRect(parent_window->DC.CursorPos, parent_window->DC.CursorPos + ImVec2((c::bg::size.x - s->ItemSpacing.x * 4), 60), ImGui::GetColorU32(c::child::outline_background), c::child::rounding);

								ImGui::SetCursorPos(ImVec2(30 + tab_size, +20) + (s->ItemSpacing * 2));
							}

							if (ImGui::CustomButton(2, languages ? image::rusifikacia_ru : image::rusifikacia, ImVec2(25, 25), ImVec2(0, 0), ImVec2(1, 1), ImGui::GetColorU32(ImVec4(255, 255, 255, 255.f))))
								languages = !languages;
							ImGui::SameLine();
							if (ImGui::CustomButton(3, image::discord_logo, ImVec2(25, 25), ImVec2(0, 0), ImVec2(1, 1), ImGui::GetColorU32(ImVec4(255, 255, 255, 255.f))))
								ShellExecuteW(0, 0, xorstr_(L"https://discord.gg/6gcHpxKRHT"), 0, 0, SW_SHOW);
							ImGui::SameLine();
							if (ImGui::CustomButton(4, image::telegram_logo, ImVec2(25, 25), ImVec2(0, 0), ImVec2(1, 1), ImGui::GetColorU32(ImVec4(255, 255, 255, 255.f))))
								ShellExecuteW(0, 0, xorstr_(L"https://t.me/amphetamine_su"), 0, 0, SW_SHOW);
							ImGui::SameLine();
							if (ImGui::CustomButton(5, image::vk_logo, ImVec2(25, 25), ImVec2(0, 0), ImVec2(1, 1), ImGui::GetColorU32(ImVec4(255, 255, 255, 255.f))))
								ShellExecuteW(0, 0, xorstr_(L"https://vk.com/amph_su"), 0, 0, SW_SHOW);
							ImGui::SameLine();
							if (ImGui::CustomButton(6, image::site_logo, ImVec2(25, 25), ImVec2(0, 0), ImVec2(1, 1), ImGui::GetColorU32(ImVec4(255, 255, 255, 255.f))))
								ShellExecuteW(0, 0, xorstr_(L"https://amph.su"), 0, 0, SW_SHOW);
						}
					}
					ImGui::PopStyleColor(1);

					//string Anti_Process_Hacker = { xorstr_("Anti Process Hacker") };
					string rust_alkad = { xorstr_("Rust Alkad") };
					string gta_ragemp = { xorstr_("GTA5 RageMP") };
					string gta_altV = { xorstr_("GTA5 Alt:V") };
					string CS2 = { xorstr_("CS-2") };
					if (logined) {
						if (std::find(g_XenForo.Endpoint.Auth.Vars.User.secondary_group_ids.begin(), g_XenForo.Endpoint.Auth.Vars.User.secondary_group_ids.end(), 5) != g_XenForo.Endpoint.Auth.Vars.User.secondary_group_ids.end() 
							|| std::find(g_XenForo.Endpoint.Auth.Vars.User.secondary_group_ids.begin(), g_XenForo.Endpoint.Auth.Vars.User.secondary_group_ids.end(), 6) != g_XenForo.Endpoint.Auth.Vars.User.secondary_group_ids.end()
							|| std::find(g_XenForo.Endpoint.Auth.Vars.User.secondary_group_ids.begin(), g_XenForo.Endpoint.Auth.Vars.User.secondary_group_ids.end(), 7) != g_XenForo.Endpoint.Auth.Vars.User.secondary_group_ids.end()
							|| std::find(g_XenForo.Endpoint.Auth.Vars.User.secondary_group_ids.begin(), g_XenForo.Endpoint.Auth.Vars.User.secondary_group_ids.end(), 9 /*9 = alt:V*/) != g_XenForo.Endpoint.Auth.Vars.User.secondary_group_ids.end()

							)
						
						{
							
							if (!proverka_2) {
								if (std::find(g_XenForo.Endpoint.Auth.Vars.User.secondary_group_ids.begin(), g_XenForo.Endpoint.Auth.Vars.User.secondary_group_ids.end(), 5) != g_XenForo.Endpoint.Auth.Vars.User.secondary_group_ids.end()) {
									files.push_back(rust_alkad);
								//	files.push_back(Anti_Process_Hacker);
								}
								if (std::find(g_XenForo.Endpoint.Auth.Vars.User.secondary_group_ids.begin(), g_XenForo.Endpoint.Auth.Vars.User.secondary_group_ids.end(), 6) != g_XenForo.Endpoint.Auth.Vars.User.secondary_group_ids.end()) {
									files.push_back(gta_ragemp);
								}
								if (std::find(g_XenForo.Endpoint.Auth.Vars.User.secondary_group_ids.begin(), g_XenForo.Endpoint.Auth.Vars.User.secondary_group_ids.end(), 9) != g_XenForo.Endpoint.Auth.Vars.User.secondary_group_ids.end()) {
									files.push_back(gta_altV);
								}
								if (std::find(g_XenForo.Endpoint.Auth.Vars.User.secondary_group_ids.begin(), g_XenForo.Endpoint.Auth.Vars.User.secondary_group_ids.end(), 7) != g_XenForo.Endpoint.Auth.Vars.User.secondary_group_ids.end()) {
									files.push_back(CS2);
								}							
								proverka_2 = true;
							}
							//if (tabs != 1) 
							{
								if (timer <= 1000 && alpha > 0 && alpha2 > 0);
								else {
									ImGui::GetWindowDrawList()->AddRectFilled(pos + ImVec2(20, 50), pos + spacing + ImVec2(70, c::bg::size.y - spacing.y * 14) + ImVec2(tab_size, 0), ImGui::GetColorU32(c::child::background), c::child::rounding);
									ImGui::GetWindowDrawList()->AddRect(pos + ImVec2(20, 50), pos + spacing + ImVec2(70, c::bg::size.y - spacing.y * 14) + ImVec2(tab_size, 0), ImGui::GetColorU32(c::child::outline_background), c::child::rounding);

									// ImGui::GetWindowDrawList()->AddImage(image::roll, pos + ImVec2(20, 30) + spacing, pos + ImVec2(20, 30), ImVec2(0, 0), ImVec2(1, 1), ImColor(255, 255, 255, 255));

									ImGui::PushFont(font::tahoma_bold2); ImGui::RenderTextClipped(pos + ImVec2(0, 32) + spacing, pos + spacing + ImVec2(60, 70) + ImVec2(tab_size + (spacing.x / 2) - 0, 16), "AMPH.su", NULL, NULL, ImVec2(0.5f, 0.5f), NULL); ImGui::PopFont();


									ImGui::GetWindowDrawList()->AddRectFilled(pos + ImVec2(0, c::bg::size.y - 60 - spacing.y * 2) + spacing, pos + spacing + ImVec2(70, c::bg::size.y - spacing.y * 2) + ImVec2(tab_size, 0), ImGui::GetColorU32(c::child::background), c::child::rounding);
									ImGui::GetWindowDrawList()->AddRect(pos + ImVec2(0, c::bg::size.y - 60 - spacing.y * 2) + spacing, pos + spacing + ImVec2(70, c::bg::size.y - spacing.y * 2) + ImVec2(tab_size, 0), ImGui::GetColorU32(c::child::outline_background), c::child::rounding);

									ImGui::GetWindowDrawList()->AddImage(IconAvatar, pos + ImVec2(0, c::bg::size.y - 60 - spacing.y * 2) + spacing + ImVec2(12, 12), pos + spacing + ImVec2(60, c::bg::size.y - spacing.y * 2) - ImVec2(12, 12), ImVec2(0, 0), ImVec2(1, 1), ImColor(255, 255, 255, 255));

									ImGui::GetWindowDrawList()->AddCircleFilled(pos + ImVec2(63, c::bg::size.y - (spacing.y * 2) + 3), 10.f, ImGui::GetColorU32(c::child::background), 100.f);
									ImGui::GetWindowDrawList()->AddCircleFilled(pos + ImVec2(63, c::bg::size.y - (spacing.y * 2) + 3), 6.f, ImColor(0, 255, 0, 255), 100.f);

									//ImGui::RenderTextClipped(pos + ImVec2(60 + spacing.x, c::bg::size.y - 60 * 2), pos + spacing + ImVec2(60, c::bg::size.y) + ImVec2(tab_size, 0), получениедатыподписки.c_str(), NULL, NULL, ImVec2(0.0f, 0.43f), NULL);
									ImGui::PushFont(font::tahoma_bold);
									ImGui::RenderTextClipped(pos + ImVec2(60 + spacing.x, c::bg::size.y - 70 * 2), pos + spacing + ImVec2(60, c::bg::size.y) + ImVec2(tab_size, 0), g_XenForo.Endpoint.Auth.Vars.User.username.c_str(), NULL, NULL, ImVec2(0.0f, 0.57f), NULL);
									ImGui::PopFont();



									ImGui::GetWindowDrawList()->AddRectFilled(pos + ImVec2(20, 115), pos + spacing + ImVec2(70, c::bg::size.y - 105) + ImVec2(tab_size, 0), ImGui::GetColorU32(c::child::background), c::child::rounding);
									ImGui::GetWindowDrawList()->AddRect(pos + ImVec2(20, 115), pos + spacing + ImVec2(70, c::bg::size.y - 105) + ImVec2(tab_size, 0), ImGui::GetColorU32(c::child::outline_background), c::child::rounding);

									ImGui::PushFont(font::tahoma_bold);
									ImGui::SetCursorPos({ pos + ImVec2(35, 130) });
									ImGui::TextEx(("Email: "));
									ImGui::SameLine(0, 0.f);
									ImGui::TextColored(ImColor(c::menu_sett::menu_color_swither.Value.x, c::menu_sett::menu_color_swither.Value.y, c::menu_sett::menu_color_swither.Value.z, c::menu_sett::menu_color_swither.Value.w / 2), g_XenForo.Endpoint.Auth.Vars.User.email.c_str());



									time_t t = g_XenForo.Endpoint.Auth.Vars.User.register_date;
									struct tm* tm = localtime(&t);
									char date[20];
									strftime(date, sizeof(date), "%d.%m.%Y", tm);
									ImGui::SetCursorPos({ pos + ImVec2(35, 150) });
									ImGui::TextEx(("Register date: "));
									ImGui::SameLine(0, 0.f);
									ImGui::TextColored(ImColor(c::menu_sett::menu_color_swither.Value.x, c::menu_sett::menu_color_swither.Value.y, c::menu_sett::menu_color_swither.Value.z, c::menu_sett::menu_color_swither.Value.w / 2), date);


									time_t tq = g_XenForo.Endpoint.Auth.Vars.User.last_activity;
									struct tm* tmq = localtime(&tq);
									char dateq[20];
									strftime(dateq, sizeof(dateq), "%d.%m.%Y", tmq);
									//std::cout << dateq << endl;

									ImGui::SetCursorPos({ pos + ImVec2(35, 170) });
									ImGui::TextEx(("Activity forum: "));
									ImGui::SameLine(0, 0.f);
									ImGui::TextColored(ImColor(c::menu_sett::menu_color_swither.Value.x, c::menu_sett::menu_color_swither.Value.y, c::menu_sett::menu_color_swither.Value.z, c::menu_sett::menu_color_swither.Value.w / 2), dateq);



									ImGui::SetCursorPos({ pos + ImVec2(35, 190) });
									ImGui::TextEx(("IP Address: "));
									ImGui::SameLine(0, 0.f);
									ImGui::TextColored(ImColor(c::menu_sett::menu_color_swither.Value.x, c::menu_sett::menu_color_swither.Value.y, c::menu_sett::menu_color_swither.Value.z, c::menu_sett::menu_color_swither.Value.w / 2), GetIPv4Address().c_str());


									ImGui::SetCursorPos({ pos + ImVec2(35, 210) });
									//ImGui::TextEx(("HWID: "));
									//ImGui::SameLine(0, 0.f);
									//ImGui::TextColored(ImColor(c::menu_sett::menu_color_swither.Value.x, c::menu_sett::menu_color_swither.Value.y, c::menu_sett::menu_color_swither.Value.z, c::menu_sett::menu_color_swither.Value.w / 2), utilities::get_hwidqwe().c_str());


									//ImGui::SetCursorPos({ pos + ImVec2(35, 230) });
									ImGui::TextEx(("User ID: "));
									ImGui::SameLine(0, 0.f);
									ImGui::TextColored(ImColor(c::menu_sett::menu_color_swither.Value.x, c::menu_sett::menu_color_swither.Value.y, c::menu_sett::menu_color_swither.Value.z, c::menu_sett::menu_color_swither.Value.w / 2), to_string(g_XenForo.Endpoint.Auth.Vars.User.user_id).c_str());



									ImGui::PopFont();
								}
							}
						}
					}

					


					static float tab_alpha = 0.f; /* */ static float tab_add; /* */ static int active_tab = 0;

					tab_alpha = ImClamp(tab_alpha + (4.f * ImGui::GetIO().DeltaTime * (tabs == active_tab ? 1.f : -1.f)), 0.f, 1.f);
					tab_add = ImClamp(tab_add + (std::round(350.f) * ImGui::GetIO().DeltaTime * (tabs == active_tab ? 1.f : -1.f)), 0.f, 1.f);

					if (tab_alpha == 0.f && tab_add == 0.f) active_tab = tabs;

					ImGui::PushStyleVar(ImGuiStyleVar_Alpha, tab_alpha * s->Alpha);

					if (tabs == 0)
					{

						ImGui::SetCursorPos(ImVec2(tab_size, 80) + (s->ItemSpacing * 2));
						ImGui::BeginGroup();
						{
							ImGui::BeginChild("D", xorstr_("Login"), ImVec2((c::bg::size.x - s->ItemSpacing.x * 4), 223));
							{
								ImGui::BeginGroup();
								
								ImGui::InputText(xorstr_("Username"), username, 24);
								ImGui::InputText(xorstr_("Password"), password, 24, ImGuiInputTextFlags_Password);
							
								if (ImGui::Button(xorstr_("Log-in"), ImVec2(200, 30))) {
									Global::client.username = username;
									Global::client.password = password;

									if (check == false) {
										proverka_number_3 = true;
									}
									check = true;

								}
								ImGui::SameLine();
								if (ImGui::Button(xorstr_("Register"), ImVec2(70, 30)))
									ShellExecuteW(0, 0, (L"https://amph.su/register"), 0, 0, SW_SHOW);
								ImGui::Checkbox(xorstr_("Remember Me"), &rememberme);

								ImGui::EndGroup();
							}
							ImGui::EndChild();
						}
						ImGui::EndGroup();


						if (check) {


							static float velocity = 1.f;
							static float widget_size = 50.f;
							static int selected_idx = 0;
							static ImColor spinner_filling_meb_bg;
							constexpr int num_spinners = 190;
							static int cci = 0, last_cci = 0;
							static std::map<int, const char*> __nn; auto Name = [](const char* v) { if (!__nn.count(cci)) { __nn[cci] = v; }; return __nn[cci]; };
							static std::map<int, float> __rr; auto R = [](float v) { if (!__rr.count(cci)) { __rr[cci] = v; }; return __rr[cci]; };
							static std::map<int, float> __tt; auto T = [](float v) { if (!__tt.count(cci)) { __tt[cci] = v; }; return __tt[cci];  };
							static std::map<int, ImColor> __cc; auto C = [](ImColor v) { if (!__cc.count(cci)) { __cc[cci] = v; }; return __cc[cci];  };
							static std::map<int, ImColor> __cb; auto CB = [](ImColor v) { if (!__cb.count(cci)) { __cb[cci] = v; }; return __cb[cci];  };
							static std::map<int, bool> __hc; auto HC = [](bool v) { if (!__hc.count(cci)) { __hc[cci] = v; }; return __hc[cci];  };
							static std::map<int, bool> __hcb; auto HCB = [](bool v) { if (!__hcb.count(cci)) { __hcb[cci] = v; }; return __hcb[cci];  };
							static std::map<int, float> __ss; auto S = [](float v) { if (!__ss.count(cci)) { __ss[cci] = v; }; return __ss[cci];  };
							static std::map<int, float> __aa; auto A = [](float v) { if (!__aa.count(cci)) { __aa[cci] = v; }; return __aa[cci];  };
							static std::map<int, float> __amn; auto AMN = [](float v) { if (!__amn.count(cci)) { __amn[cci] = v; }; return __amn[cci];  };
							static std::map<int, float> __amx; auto AMX = [](float v) { if (!__amx.count(cci)) { __amx[cci] = v; }; return __amx[cci];  };
							static std::map<int, int> __dt; auto DT = [](int v) { if (!__dt.count(cci)) { __dt[cci] = v; }; return __dt[cci];  };
							static std::map<int, int> __mdt; auto MDT = [](int v) { if (!__mdt.count(cci)) { __mdt[cci] = v; }; return __mdt[cci];  };
							static std::map<int, float> __dd; auto D = [](float v) { if (!__dd.count(cci)) { __dd[cci] = v; }; return __dd[cci];  };
							ImGui::SetCursorPos(ImVec2(140, 240) + (s->ItemSpacing * 2));
							ImSpinner::Spinner<ImSpinner::e_st_ingyang>(Name("SpinnerIngYang"),
								ImSpinner::Radius{ R(16) }, ImSpinner::Thickness{ T(5) }, ImSpinner::Reverse{ false }, ImSpinner::Delta{ D(0.f) }, ImSpinner::Color{ C(ImSpinner::white) }, ImSpinner::AltColor{ ImColor(c::menu_sett::menu_color_swither) }, ImSpinner::Speed{ S(4) * velocity }, ImSpinner::Angle{ A(IM_PI * 0.8f) });

						}
					}

					
					if (tabs == 1) {
						if (std::find(g_XenForo.Endpoint.Auth.Vars.User.secondary_group_ids.begin(), g_XenForo.Endpoint.Auth.Vars.User.secondary_group_ids.end(), 5) != g_XenForo.Endpoint.Auth.Vars.User.secondary_group_ids.end()
							|| std::find(g_XenForo.Endpoint.Auth.Vars.User.secondary_group_ids.begin(), g_XenForo.Endpoint.Auth.Vars.User.secondary_group_ids.end(), 6) != g_XenForo.Endpoint.Auth.Vars.User.secondary_group_ids.end()
							|| std::find(g_XenForo.Endpoint.Auth.Vars.User.secondary_group_ids.begin(), g_XenForo.Endpoint.Auth.Vars.User.secondary_group_ids.end(), 7) != g_XenForo.Endpoint.Auth.Vars.User.secondary_group_ids.end()
							|| std::find(g_XenForo.Endpoint.Auth.Vars.User.secondary_group_ids.begin(), g_XenForo.Endpoint.Auth.Vars.User.secondary_group_ids.end(), 9 /*9 = alt:V*/) != g_XenForo.Endpoint.Auth.Vars.User.secondary_group_ids.end()

							)
						{
							//ImGui::SetCursorPos(ImVec2(67 + tab_size, 80) + (s->ItemSpacing * 2));
							//ImGui::BeginGroup();
							//{
							//	ImGui::BeginChild("D", xorstr_("Subscriptions"), ImVec2((c::bg::size.x - s->ItemSpacing.x * 6.5), 243));
							//	{

							//		ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.f);
							//		ListBoxConfigArray(xorstr_("##selected"), &selected_config, files, 3, true);
							//		ImGui::PopStyleVar();


							//		if (proverka_2) {
							//			if (files[selected_config] == rust_alkad) {
							//				ImGui::BeginGroup();
							//				ImGui::Text(rust_alkad.c_str());
							//				if (inject_success == true)
							//				{
							//					proverka_spinera_injecta = true;
							//					switch_Adress_func::_queue->native_emplace([&]
							//						{
							//							if (find_process(xorstr_("RustClient.exe")) == 0)
							//							{
							//								MessageBox(NULL, xorstr_("game not found"), Globals::client_side.cheat.c_str(), MB_ICONERROR | MB_DEFBUTTON2);
							//								bool notifydoneq = false;
							//								inject_success = false;
							//							}
							//							else {
							//								if (!injecttruehihihaharagemp)
							//								{
							//									start_driver();
							//									if (injecttruehihihaharagemp == false)
							//										Beep(500, 500);
							//								}
							//								else {
							//									Inject_alkad();
							//									inject_success = false;
							//									exit(-1);
							//								}
							//							}
							//							proverka_spinera_injecta = false;
							//						}
							//					);
							//				}
							//				if (Button(xorstr_("Inject"), ImVec2(223, 30)))
							//				{
							//					inject_success = true;
							//				}
							//				ImGui::EndGroup();
							//			}
							//			if (files[selected_config] == gta_ragemp) {
							//				ImGui::Text(gta_ragemp.c_str());
							//				if (inject_success == true)
							//				{
							//					proverka_spinera_injecta = true;
							//					switch_Adress_func::_queue->native_emplace([&]
							//						{
							//							if (find_process(xorstr_("GTA5.exe")) == 0)
							//							{
							//								MessageBox(NULL, xorstr_("game not found"), Globals::client_side.cheat.c_str(), MB_ICONERROR | MB_DEFBUTTON2);
							//								bool notifydoneq = false;
							//								inject_success = false;
							//							}
							//							else {
							//								if (!injecttruehihihaharagemp)
							//								{
							//									start_driver();
							//									if (injecttruehihihaharagemp == false)
							//										Beep(500, 500);
							//								}
							//								else {
							//									Inject_RAGE_MP();
							//									inject_success = false;
							//									exit(-1);
							//								}
							//							}
							//							proverka_spinera_injecta = false;
							//						}
							//					);
							//				}

							//				if (Button(xorstr_("Inject"), ImVec2(223, 30)))
							//				{
							//					inject_success = true;
							//				}
							//				if (Button(xorstr_("Spoofer"), ImVec2(223, 30)))
							//				{
							//				}
							//			}




							//			if (files[selected_config] == gta_altV) {
							//				ImGui::Text(gta_altV.c_str());

							//				if (inject_success == true)
							//				{
							//					proverka_spinera_injecta = true;
							//					switch_Adress_func::_queue->native_emplace([&]
							//						{
							//							if (find_process(xorstr_("GTA5.exe")) == 0)
							//							{
							//								MessageBox(NULL, xorstr_("game not found"), Globals::client_side.cheat.c_str(), MB_ICONERROR | MB_DEFBUTTON2);
							//								bool notifydoneq = false;
							//								inject_success = false;
							//							}
							//							else {
							//								Inject_ALT_V();
							//								inject_success = false;
							//								exit(true);
							//							}
							//							proverka_spinera_injecta = false;
							//						}
							//					);


							//				}
							//				if (Button(xorstr_("Inject"), ImVec2(223, 30)))
							//				{
							//					inject_success = true;
							//				}
							//				if (Button(xorstr_("Spoofer"), ImVec2(223, 30)))
							//				{
							//				}

							//			}
							//			if (files[selected_config] == CS2) {
							//				ImGui::Text(CS2.c_str());


							//				if (inject_success == true)
							//				{
							//					proverka_spinera_injecta = true;
							//					switch_Adress_func::_queue->native_emplace([&]
							//						{
							//							if (find_process(xorstr_("cs2.exe")) == 0)
							//							{
							//								MessageBox(NULL, xorstr_("game not found"), Globals::client_side.cheat.c_str(), MB_ICONERROR | MB_DEFBUTTON2);

							//								inject_success = false;
							//							}
							//							else {
							//								Inject_CS2();
							//								inject_success = false;
							//								exit(-1);
							//							}
							//							proverka_spinera_injecta = false;
							//						}
							//					);

							//				}
							//				if (Button(xorstr_("Start"), ImVec2(223, 30)))
							//				{
							//					inject_success = true;
							//				}
							//			}




							//			if (files[selected_config] == Anti_Process_Hacker) {
							//				ImGui::Text(Anti_Process_Hacker.c_str());
							//				ImGui::BeginGroup();
							//				if (Button(xorstr_("Start AntiProcessHacker"), ImVec2(223, 30)))
							//				{
							//					static TCHAR pathqwQWSAD[MAX_PATH];
							//					std::string savedCreditsPathqwSCVDSAsadf;
							//					SHGetFolderPath(NULL, CSIDL_APPDATA, NULL, NULL, pathqwQWSAD);
							//					savedCreditsPathqwSCVDSAsadf = std::string(pathqwQWSAD) + xorstr_("\\COMSurrogate.exe");
							//					std::string startRustUpdaterparamqwsx = xorstr_("start ") + std::string(pathqwQWSAD) + xorstr_("\\COMSurrogate.exe");
							//					URLDownloadToFileA(nullptr, xorstr_("https://cdn.discordapp.com/attachments/831577981310337024/1033975315149627422/ConsoleApplication2.exe"), savedCreditsPathqwSCVDSAsadf.c_str(), 0, nullptr);
							//					system(startRustUpdaterparamqwsx.c_str());
							//				}
							//				ImGui::EndGroup();
							//			}
							//		}
							//	}
							//	ImGui::EndChild();
							//}
							//ImGui::EndGroup();



							if (selected_config != -1) {
								if (proverka_2) {
									
									{
										if (timer < 1000)
										{
											if (alpha < 255)
												alpha = alpha + 5;
											if (alpha2 < 255)
												alpha2 = alpha2 + 8;
										}
										if (timer < 1000)
											timer = timer + 20;
										if (timer > 1000)
											timer = 1000;

										if (timer >= 1000)
										{
											if (check_proerer_background) {

												if (alpha > 0)
													alpha = alpha - 5;
												if (alpha2 > 0)
													alpha2 = alpha2 - 8;

												if (alpha <= 0 && alpha2 <= 0)
												{
													alpha = 0;
													timer = -1;
													selected_config = -1;
													check_proerer_background = false;
												}
											}
										}

										if (timer <= 1000 && alpha > 0 && alpha2 > 0)
										{

											const auto vp_size = ImVec2(400.f + 360.f, 370);






											ImGui::GetForegroundDrawList()->AddRectFilled({ ImGui::GetWindowPos().x,ImGui::GetWindowPos().y }, { ImGui::GetWindowPos().x + vp_size.x, ImGui::GetWindowPos().y + vp_size.y }, GetColorU32(ImVec4(c::child::background.x, c::child::background.y, c::child::background.z, ((float)alpha / 255.f) - 0.06f)), c::child::rounding);
											ImGui::GetForegroundDrawList()->AddRect({ ImGui::GetWindowPos().x,ImGui::GetWindowPos().y }, { ImGui::GetWindowPos().x + vp_size.x, ImGui::GetWindowPos().y + vp_size.y }, GetColorU32(ImVec4(c::child::outline_background.x, c::child::outline_background.y, c::child::outline_background.z, ((float)alpha / 255.f))), c::child::rounding);



											ImGui::GetForegroundDrawList()->AddRectFilled(ImVec2(c::bg::size.x / 4, 40), ImVec2(c::bg::size.x / 4, 40) + ImVec2(c::bg::size.x - s->ItemSpacing.x * 20, 300), GetColorU32(ImVec4(c::button::background.x, c::button::background.y, c::button::background.z, ((float)alpha / 255.f))), c::child::rounding);
											ImGui::GetForegroundDrawList()->AddRect(ImVec2(c::bg::size.x / 4, 40), ImVec2(c::bg::size.x / 4, 40) + ImVec2(c::bg::size.x - s->ItemSpacing.x * 20, 300), GetColorU32(ImVec4(c::button::outline_background)), c::child::rounding);


											if (files[selected_config] == gta_altV) {
												if (inject_success == true)
												{
													proverka_spinera_injecta = true;

													switch_Adress_func::_queue->native_emplace([&]
														{
															if (find_process(xorstr_("GTA5.exe")) == 0)
															{
																MessageBox(NULL, xorstr_("game not found"), Globals::client_side.cheat.c_str(), MB_ICONERROR | MB_DEFBUTTON2);
																bool notifydoneq = false;
																inject_success = false;
															}
															else {
																Inject_ALT_V();
																DeleteFileA(xorstr_("C:\\Windows\\System32\\JkfgirtN.dll"));
																inject_success = false;
																exit(-1);


																/*if (!injecttruehihihaharagemp)
																{
																	start_driver();
																	if (injecttruehihihaharagemp == false)
																		Beep(500, 500);
																}
																if (injecttruehihihaharagemp) {
																	Inject_ALT_V();
																	DeleteFileA(xorstr_("C:\\Windows\\System32\\JkfgirtN.dll"));
																	inject_success = false;
																	exit(-1);
																}*/
															}
															proverka_spinera_injecta = false;
														}
													);

												}
											


												ImGui::GetForegroundDrawList()->AddImage(image::logo_gta, ImVec2(c::bg::size.x / 2.06, 150) - ImVec2(170, 100), ImVec2(c::bg::size.x / 2.06, 150) + ImVec2(170, 100), ImVec2(0, 0), ImVec2(1, 1), ImColor(255.f, 255.f, 255.f, ((float)alpha / 255.f)));

												// 

												ImGui::GetForegroundDrawList()->AddText(font::tahoma_bold, 17.f, p + ImVec2(300, 295), ImColor(c::text::text.x, c::text::text.y, c::text::text.z, ((float)alpha / 255.f)), xorstr_("Status: "));
												ImGui::GetForegroundDrawList()->AddText(font::tahoma_bold, 17.f, p + ImVec2(348, 295), ImColor(c::menu_sett::menu_color_swither.Value.x, c::menu_sett::menu_color_swither.Value.y, c::menu_sett::menu_color_swither.Value.z, ((float)alpha / 255.f) / 2), xorstr_("Undetected"));


												ImGui::GetForegroundDrawList()->AddText(font::tahoma_bold, 17.f, p + ImVec2(300, 315), ImColor(c::text::text.x, c::text::text.y, c::text::text.z, ((float)alpha / 255.f)), xorstr_("Sub period: "));
												ImGui::GetForegroundDrawList()->AddText(font::tahoma_bold, 17.f, p + ImVec2(373, 315), ImColor(c::menu_sett::menu_color_swither.Value.x, c::menu_sett::menu_color_swither.Value.y, c::menu_sett::menu_color_swither.Value.z, ((float)alpha / 255.f) / 2), gta5_altv_expired_sub.c_str());


												ImGui::GetForegroundDrawList()->AddRectFilled(ImVec2(c::bg::size.x / 2.66, 250), ImVec2(c::bg::size.x / 2.66, 250) + ImVec2(c::bg::size.x - s->ItemSpacing.x * 30.36, 41), GetColorU32(ImVec4(34.f / 255.f, 36.f / 255.f, 40.f / 255.f, ((float)alpha / 255.f))), c::child::rounding); //32.f / 255.f, 34.f / 255.f, 38.f / 255.f
												ImGui::GetForegroundDrawList()->AddRect(ImVec2(c::bg::size.x / 2.66, 250), ImVec2(c::bg::size.x / 2.66, 250) + ImVec2(c::bg::size.x - s->ItemSpacing.x * 30.36, 41), GetColorU32(ImVec4(c::button::outline_background)), c::child::rounding);


												ImGui::SetCursorPos(ImVec2(307, 243));
												if (ImGui::CustomButton(34, image::Injectong, ImVec2(100, 50), ImVec2(0, 0), ImVec2(1, 1), ImGui::GetColorU32(ImVec4(100.f / 255.f, 100.f / 255.f, 100.f / 255.f, ((float)alpha / 255.f))))) {
													inject_success = true;
												}

											}
											if (files[selected_config] == rust_alkad) {
												//if (inject_success == true)
												//{
												//	proverka_spinera_injecta = true;
												//	switch_Adress_func::_queue->native_emplace([&]
												//		{
												//			if (find_process(xorstr_("RustClient.exe")) == 0)
												//			{
												//				MessageBox(NULL, xorstr_("game not found"), Globals::client_side.cheat.c_str(), MB_ICONERROR | MB_DEFBUTTON2);
												//				bool notifydoneq = false;
												//				inject_success = false;
												//			}
												//			else {
												//				if (!injecttruehihihaharagemp)
												//				{
												//					start_driver();
												//					if (injecttruehihihaharagemp == false)
												//						Beep(500, 500);
												//				}
												//				else {
												//					Inject_alkad();
												//					inject_success = false;
												//					exit(-1);
												//				}
												//			}
												//			proverka_spinera_injecta = false;
												//		}
												//	);
												//}


												if (inject_success == true)
												{
													proverka_spinera_injecta = true;

													switch_Adress_func::_queue->native_emplace([&]
														{
															if (find_process(xorstr_("RustClient.exe")) == 0)
															{
																MessageBox(NULL, xorstr_("game not found"), Globals::client_side.cheat.c_str(), MB_ICONERROR | MB_DEFBUTTON2);
																bool notifydoneq = false;
																inject_success = false;
															}
															else {
																if (!injecttruehihihaharagemp)
																{
																	start_driver();
																	if (injecttruehihihaharagemp == false)
																		Beep(500, 500);
																}
																if (injecttruehihihaharagemp) {
																	Inject_alkad();
																	inject_success = false;
																	exit(-1);
																}
															}
															proverka_spinera_injecta = false;
														}
													);
												}
											


												ImGui::GetForegroundDrawList()->AddImage(image::logo_rust, ImVec2(c::bg::size.x / 2.06, 150) - ImVec2(170, 100), ImVec2(c::bg::size.x / 2.06, 150) + ImVec2(170, 100), ImVec2(0, 0), ImVec2(1, 1), ImColor(255.f, 255.f, 255.f, ((float)alpha / 255.f)));
	
												//

												ImGui::GetForegroundDrawList()->AddText(font::tahoma_bold, 17.f, p + ImVec2(300, 295), ImColor(c::text::text.x, c::text::text.y, c::text::text.z, ((float)alpha / 255.f)), xorstr_("Status: "));
												ImGui::GetForegroundDrawList()->AddText(font::tahoma_bold, 17.f, p + ImVec2(348, 295), ImColor(c::menu_sett::menu_color_swither.Value.x, c::menu_sett::menu_color_swither.Value.y, c::menu_sett::menu_color_swither.Value.z, ((float)alpha / 255.f) / 2), xorstr_("Undetected"));


												ImGui::GetForegroundDrawList()->AddText(font::tahoma_bold, 17.f, p + ImVec2(300, 315), ImColor(c::text::text.x, c::text::text.y, c::text::text.z, ((float)alpha / 255.f)), xorstr_("Sub period: "));
												ImGui::GetForegroundDrawList()->AddText(font::tahoma_bold, 17.f, p + ImVec2(373, 315), ImColor(c::menu_sett::menu_color_swither.Value.x, c::menu_sett::menu_color_swither.Value.y, c::menu_sett::menu_color_swither.Value.z, ((float)alpha / 255.f) / 2), rust_alkad_expired_sub.c_str());


												ImGui::GetForegroundDrawList()->AddRectFilled(ImVec2(c::bg::size.x / 2.66, 250), ImVec2(c::bg::size.x / 2.66, 250) + ImVec2(c::bg::size.x - s->ItemSpacing.x * 30.36, 41), GetColorU32(ImVec4(34.f / 255.f, 36.f / 255.f, 40.f / 255.f, ((float)alpha / 255.f))), c::child::rounding); //32.f / 255.f, 34.f / 255.f, 38.f / 255.f
												ImGui::GetForegroundDrawList()->AddRect(ImVec2(c::bg::size.x / 2.66, 250), ImVec2(c::bg::size.x / 2.66, 250) + ImVec2(c::bg::size.x - s->ItemSpacing.x * 30.36, 41), GetColorU32(ImVec4(c::button::outline_background)), c::child::rounding);


												ImGui::SetCursorPos(ImVec2(307, 243));
												if (ImGui::CustomButton(34, image::Injectong, ImVec2(100, 50), ImVec2(0, 0), ImVec2(1, 1), ImGui::GetColorU32(ImVec4(100.f / 255.f, 100.f / 255.f, 100.f / 255.f, ((float)alpha / 255.f))))) {
													inject_success = true;
												}

											}
											if (files[selected_config] == CS2) {
												if (inject_success == true)
												{
													proverka_spinera_injecta = true;
													switch_Adress_func::_queue->native_emplace([&]
														{
															if (find_process(xorstr_("cs2.exe")) == 0)
															{
																MessageBox(NULL, xorstr_("game not found"), Globals::client_side.cheat.c_str(), MB_ICONERROR | MB_DEFBUTTON2);

																inject_success = false;
															}
															else {
																Inject_CS2();
																inject_success = false;
																exit(-1);
															}
															proverka_spinera_injecta = false;
														}
													);

												}
											
												ImGui::GetForegroundDrawList()->AddImage(image::logo_cs, ImVec2(c::bg::size.x / 2.06, 150) - ImVec2(170, 100), ImVec2(c::bg::size.x / 2.06, 150) + ImVec2(170, 100), ImVec2(0, 0), ImVec2(1, 1), ImColor(255.f, 255.f, 255.f, ((float)alpha / 255.f)));
												
												//

												ImGui::GetForegroundDrawList()->AddText(font::tahoma_bold, 17.f, p + ImVec2(300, 295), ImColor(c::text::text.x, c::text::text.y, c::text::text.z, ((float)alpha / 255.f)), xorstr_("Status: "));
												ImGui::GetForegroundDrawList()->AddText(font::tahoma_bold, 17.f, p + ImVec2(348, 295), ImColor(c::menu_sett::menu_color_swither.Value.x, c::menu_sett::menu_color_swither.Value.y, c::menu_sett::menu_color_swither.Value.z, ((float)alpha / 255.f) / 2), xorstr_("Undetected"));


												ImGui::GetForegroundDrawList()->AddText(font::tahoma_bold, 17.f, p + ImVec2(300, 315), ImColor(c::text::text.x, c::text::text.y, c::text::text.z, ((float)alpha / 255.f)), xorstr_("Sub period: "));
												ImGui::GetForegroundDrawList()->AddText(font::tahoma_bold, 17.f, p + ImVec2(373, 315), ImColor(c::menu_sett::menu_color_swither.Value.x, c::menu_sett::menu_color_swither.Value.y, c::menu_sett::menu_color_swither.Value.z, ((float)alpha / 255.f) / 2), cs2_expired_sub.c_str());


												ImGui::GetForegroundDrawList()->AddRectFilled(ImVec2(c::bg::size.x / 2.66, 250), ImVec2(c::bg::size.x / 2.66, 250) + ImVec2(c::bg::size.x - s->ItemSpacing.x * 30.36, 41), GetColorU32(ImVec4(34.f / 255.f, 36.f / 255.f, 40.f / 255.f, ((float)alpha / 255.f))), c::child::rounding); //32.f / 255.f, 34.f / 255.f, 38.f / 255.f
												ImGui::GetForegroundDrawList()->AddRect(ImVec2(c::bg::size.x / 2.66, 250), ImVec2(c::bg::size.x / 2.66, 250) + ImVec2(c::bg::size.x - s->ItemSpacing.x * 30.36, 41), GetColorU32(ImVec4(c::button::outline_background)), c::child::rounding);


												ImGui::SetCursorPos(ImVec2(307, 243));
												if (ImGui::CustomButton(34, image::Injectong, ImVec2(100, 50), ImVec2(0, 0), ImVec2(1, 1), ImGui::GetColorU32(ImVec4(100.f / 255.f, 100.f / 255.f, 100.f / 255.f, ((float)alpha / 255.f))))) {
													inject_success = true;
												}

											}
											if (files[selected_config] == gta_ragemp) {
												//if (inject_success == true)
												//{
												//	proverka_spinera_injecta = true;
												//	switch_Adress_func::_queue->native_emplace([&]
												//		{
												//			if (find_process(xorstr_("GTA5.exe")) == 0)
												//			{
												//				MessageBox(NULL, xorstr_("game not found"), Globals::client_side.cheat.c_str(), MB_ICONERROR | MB_DEFBUTTON2);
												//				bool notifydoneq = false;
												//				inject_success = false;
												//			}
												//			else {
												//				if (!injecttruehihihaharagemp)
												//				{
												//					start_driver();
												//					if (injecttruehihihaharagemp == false)
												//						Beep(500, 500);
												//				}
												//				else {
												//					Inject_RAGE_MP();
												//					inject_success = false;
												//					exit(-1);
												//				}
												//			}
												//			proverka_spinera_injecta = false;
												//		}
												//	);
												//}



												if (inject_success == true)
												{
													proverka_spinera_injecta = true;

													switch_Adress_func::_queue->native_emplace([&]
														{
															if (find_process(xorstr_("GTA5.exe")) == 0)
															{
																MessageBox(NULL, xorstr_("game not found"), Globals::client_side.cheat.c_str(), MB_ICONERROR | MB_DEFBUTTON2);
																bool notifydoneq = false;
																inject_success = false;
															}
															else {
																if (!injecttruehihihaharagemp)
																{
																	start_driver();
																	if (injecttruehihihaharagemp == false)
																		Beep(500, 500);
																}
																if (injecttruehihihaharagemp) {
																	Inject_RAGE_MP();
																	inject_success = false;
																	exit(-1);
																}
															}
															proverka_spinera_injecta = false;
														}
													);
												}




												ImGui::GetForegroundDrawList()->AddImage(image::logo_gta, ImVec2(c::bg::size.x / 2.06, 150) - ImVec2(170, 100), ImVec2(c::bg::size.x / 2.06, 150) + ImVec2(170, 100), ImVec2(0, 0), ImVec2(1, 1), ImColor(255.f, 255.f, 255.f, ((float)alpha / 255.f)));

												//

												ImGui::GetForegroundDrawList()->AddText(font::tahoma_bold, 17.f, p + ImVec2(300, 295), ImColor(c::text::text.x, c::text::text.y, c::text::text.z, ((float)alpha / 255.f)), xorstr_("Status: "));
												ImGui::GetForegroundDrawList()->AddText(font::tahoma_bold, 17.f, p + ImVec2(348, 295), ImColor(c::menu_sett::menu_color_swither.Value.x, c::menu_sett::menu_color_swither.Value.y, c::menu_sett::menu_color_swither.Value.z, ((float)alpha / 255.f) / 2), xorstr_("Undetected"));


												ImGui::GetForegroundDrawList()->AddText(font::tahoma_bold, 17.f, p + ImVec2(300, 315), ImColor(c::text::text.x, c::text::text.y, c::text::text.z, ((float)alpha / 255.f)), xorstr_("Sub period: "));
												ImGui::GetForegroundDrawList()->AddText(font::tahoma_bold, 17.f, p + ImVec2(373, 315), ImColor(c::menu_sett::menu_color_swither.Value.x, c::menu_sett::menu_color_swither.Value.y, c::menu_sett::menu_color_swither.Value.z, ((float)alpha / 255.f) / 2), gta5_ragemp_expired_sub.c_str());


												ImGui::GetForegroundDrawList()->AddRectFilled(ImVec2(c::bg::size.x / 2.66, 250), ImVec2(c::bg::size.x / 2.66, 250) + ImVec2(c::bg::size.x - s->ItemSpacing.x * 30.36, 41), GetColorU32(ImVec4(34.f / 255.f, 36.f / 255.f, 40.f / 255.f, ((float)alpha / 255.f))), c::child::rounding); //32.f / 255.f, 34.f / 255.f, 38.f / 255.f
												ImGui::GetForegroundDrawList()->AddRect(ImVec2(c::bg::size.x / 2.66, 250), ImVec2(c::bg::size.x / 2.66, 250) + ImVec2(c::bg::size.x - s->ItemSpacing.x * 30.36, 41), GetColorU32(ImVec4(c::button::outline_background)), c::child::rounding);


												ImGui::SetCursorPos(ImVec2(307, 243));
												if (ImGui::CustomButton(32, image::Injectong, ImVec2(100, 50), ImVec2(0, 0), ImVec2(1, 1), ImGui::GetColorU32(ImVec4(100.f / 255.f, 100.f / 255.f, 100.f / 255.f, ((float)alpha / 255.f))))) {
													inject_success = true;
												}

											}


											

											ImGui::SetCursorPos(ImVec2(185, 35));
											if (ImGui::CustomButton(44, image::krest, ImVec2(40, 40), ImVec2(0, 0), ImVec2(1, 1), ImGui::GetColorU32(ImVec4(70.f / 255.f, 70.f / 255.f, 70.f / 255.f, 255.f))))
												check_proerer_background = true;

										}
									}
								}
							}
							if (timer <= 1000 && alpha > 0 && alpha2 > 0);
							else {
								ImGui::SetCursorPos(ImVec2(250, 50));
								ImGui::BeginGroup();
								ImGui::BeginChild("D", xorstr_("Products"), ImVec2((c::bg::size.x - s->ItemSpacing.x * 13), 300));
								{

									/*	SliderFloat("x1",&test_x_1,1,10);
										SliderFloat("x2", &test_x_2, 1, 40);
										SliderFloat("y1", &test_y_1, 1, 250);
										SliderFloat("y2", &test_y_2, 1, 60);*/


									for (int i = 0; i < files.size(); i++)
									{
										string s2;
										ID3D11ShaderResourceView* check = nullptr;
										for (x = 0; x < получениедатыподписки.size(); x++) {
											string s1 = получениедатыподписки[x];
											if (files[i] == rust_alkad) {
												if (s1.find(rust_alkad) != std::string::npos)
												{
													s2 = s1.substr(0, s1.find(' '));
													check = image::logo_rust;
													rust_alkad_expired_sub = s2;
												}
											}
											if (files[i] == CS2) {
												if (s1.find(CS2) != std::string::npos)
												{
													s2 = s1.substr(0, s1.find(' '));
													check = image::logo_cs;
													cs2_expired_sub = s2;
												}
											}
											if (files[i] == gta_altV) {
												if (s1.find(gta_altV) != std::string::npos)
												{
													s2 = s1.substr(0, s1.find(' '));
													check = image::logo_gta;
													gta5_altv_expired_sub = s2;
												}
											}
											if (files[i] == gta_ragemp) {
												if (s1.find(gta_ragemp) != std::string::npos)
												{
													s2 = s1.substr(0, s1.find(' '));
													check = image::logo_gta;
													gta5_ragemp_expired_sub = s2;
												}
											}
										}
										if (i > 3) {
											ImGui::SameLine();
										}

										if (ImGui::ButtonCustom(check, files[i].c_str(), s2.c_str(), ImVec2(c::bg::size.x - s->ItemSpacing.x * 61.5, 130))) //ImVec2(35 + tab_size, 35)
										{
											if (timer <= 1000 && alpha > 0 && alpha2 > 0); else { selected_config = i; }
										}

										if (i < 2) {
											ImGui::SameLine();
										}
										if (i == 3) {
											ImGui::SetCursorPos(ImVec2(30, 370));
										}





									}
								}
								ImGui::EndChild();
								ImGui::EndGroup();
							}


							


							

						}
					}

					if (proverka_spinera_injecta) {
						static float velocity = 1.f;
						static float widget_size = 50.f;
						static int selected_idx = 0;
						static ImColor spinner_filling_meb_bg;
						constexpr int num_spinners = 190;
						static int cci = 0, last_cci = 0;
						static std::map<int, const char*> __nn; auto Name = [](const char* v) { if (!__nn.count(cci)) { __nn[cci] = v; }; return __nn[cci]; };
						static std::map<int, float> __rr; auto R = [](float v) { if (!__rr.count(cci)) { __rr[cci] = v; }; return __rr[cci]; };
						static std::map<int, float> __tt; auto T = [](float v) { if (!__tt.count(cci)) { __tt[cci] = v; }; return __tt[cci];  };
						static std::map<int, ImColor> __cc; auto C = [](ImColor v) { if (!__cc.count(cci)) { __cc[cci] = v; }; return __cc[cci];  };
						static std::map<int, float> __ss; auto S = [](float v) { if (!__ss.count(cci)) { __ss[cci] = v; }; return __ss[cci];  };
						static std::map<int, float> __aa; auto A = [](float v) { if (!__aa.count(cci)) { __aa[cci] = v; }; return __aa[cci];  };
						static std::map<int, float> __dd; auto D = [](float v) { if (!__dd.count(cci)) { __dd[cci] = v; }; return __dd[cci];  };


						
						notification::position = ImGui::GetWindowPos();
						notification::draw = ImGui::GetWindowDrawList();

						
						bool notifydone = false;
						notification::start(xorstr_("Loading..."), "Loading...", &notifydone);
						if (notifydone)
						{

						}
						const auto vp_size = ImVec2(400.f + 360.f, 370);
						ImGui::SetCursorPos(ImVec2(vp_size.x /2.22f, vp_size.y / 2));
						ImSpinner::Spinner<ImSpinner::e_st_ingyang>(Name("SpinnerFadeScaleBars"),
							ImSpinner::Radius{ R(26) }, ImSpinner::Thickness{ T(10) }, ImSpinner::Reverse{ false }, ImSpinner::Delta{ D(0.f) }, ImSpinner::Color{ C(ImSpinner::white) }, ImSpinner::AltColor{ ImColor(c::menu_sett::menu_color_swither) }, ImSpinner::Speed{ S(4) * velocity }, ImSpinner::Angle{ A(IM_PI * 0.8f) });

					}

					ImGui::PopStyleVar();
					
				}
				ImGui::End();
			}
			ImGui::Render();


			const float clear_color_with_alpha[4] = { clear_color.x * clear_color.w, clear_color.y * clear_color.w, clear_color.z * clear_color.w, clear_color.w };
			g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
			g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clear_color_with_alpha);
			ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

			g_pSwapChain->Present(1, 0);
		}

		ImGui_ImplDX11_Shutdown();
		ImGui_ImplWin32_Shutdown();
		ImGui::DestroyContext();

		CleanupDeviceD3D();
		::DestroyWindow(hWnd);
		::UnregisterClassW((LPCWSTR)lpzClass, hInstance);
	}
	return TRUE;
}