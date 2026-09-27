export module Hook:All;

import "sys_defs.h";
import std;
import :Core;
import :Ntdll;
import :Kernel32;
import :Advapi32;
import :Shell32;
import :User32;
import :Ole32;
import :Iphlpapi;
import :Netapi32;

namespace hook
{
	export void hook_all()
	{
		wchar_t scope[16]{};
		const DWORD scopeLength = GetEnvironmentVariableW(L"WORKSPACE_HOOK_SCOPE", scope, static_cast<DWORD>(std::size(scope)));
		const bool deviceScope = scopeLength == 6 && std::wstring_view{scope, scopeLength} == L"device";
		if (!deviceScope) hook_ntdll();
		hook_kernel32(deviceScope);
		if (!deviceScope)
		{
			hook_advapi32();
			hook_shell32();
		}
		if (!deviceScope) hook_user32();
		hook_ole32();
		hook_iphlpapi();
		hook_netapi32();
		
		HookManager::instance().installAll();
	}
}
