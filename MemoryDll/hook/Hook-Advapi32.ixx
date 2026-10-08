export module Hook:Advapi32;

import "sys_defs.h";
import std;
import :Core;
import GlobalData;
import :Kernel32;

namespace hook
{
	LSTATUS APIENTRY RegLoadAppKeyW(_In_ LPCWSTR lpFile, _Out_ PHKEY phkResult, _In_ REGSAM samDesired, _In_ DWORD dwOptions, _Reserved_ DWORD Reserved)
	{
		namespace fs = std::filesystem;
		return RegCreateKeyExW(global::Data::get().appKey(),
		                       std::format(L"{}_{}", fs::path{lpFile}.stem().native(), global::Data::get().registrySuffixName()).c_str(),
		                       Reserved, nullptr, dwOptions, samDesired, nullptr, phkResult, nullptr);
	}

	BOOL GetTokenIntegrityLevel(HANDLE hToken, PDWORD pIntegrityLevel)
	{
		BOOL bReturn = FALSE;

		// First, compute the size of the buffer to get the Integrity level
		DWORD dwNeededSize = 0;
		if (!GetTokenInformation(hToken, TokenIntegrityLevel, nullptr, 0, &dwNeededSize))
		{
			if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
			{
				// Second, allocate a memory block with the required size 
				if (const PTOKEN_MANDATORY_LABEL pTokenInfo = static_cast<PTOKEN_MANDATORY_LABEL>(LocalAlloc(0, dwNeededSize)); pTokenInfo)
				{
					// And finally, ask for the integrity level
					if (GetTokenInformation(hToken, TokenIntegrityLevel, pTokenInfo, dwNeededSize, &dwNeededSize))
					{
						*pIntegrityLevel = *GetSidSubAuthority(pTokenInfo->Label.Sid, *GetSidSubAuthorityCount(pTokenInfo->Label.Sid) - 1);
						bReturn = TRUE;
					}
					LocalFree(pTokenInfo);
				}
			}
		}
		return bReturn;
	}

	BOOL GetProcessIntegrityLevel(HANDLE hProcess, PDWORD pIntegrityLevel)
	{
		HANDLE hToken = nullptr;
		if (!OpenProcessToken(hProcess, TOKEN_READ, &hToken))
		{
			return FALSE;
		}
		const BOOL bReturn = GetTokenIntegrityLevel(hToken, pIntegrityLevel);
		CloseHandle(hToken);
		return bReturn;
	}

	template <auto Trampoline>
	BOOL WINAPI CreateProcessAsUserA(_In_opt_ HANDLE hToken, _In_opt_ LPCSTR lpApplicationName, _Inout_opt_ LPSTR lpCommandLine,
	                                 _In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes, _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
	                                 _In_ BOOL bInheritHandles, _In_ DWORD dwCreationFlags, _In_opt_ LPVOID lpEnvironment,
	                                 _In_opt_ LPCSTR lpCurrentDirectory, _In_ LPSTARTUPINFOA lpStartupInfo, _Out_ LPPROCESS_INFORMATION lpProcessInformation)
	{
		const BOOL bOrigSuspended = dwCreationFlags & CREATE_SUSPENDED;
		if (!bOrigSuspended)
		{
			dwCreationFlags |= CREATE_SUSPENDED;
		}

		PROCESS_INFORMATION backup{};
		if (!lpProcessInformation)
		{
			lpProcessInformation = &backup;
		}

		if (!Trampoline(hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles,
		                dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation))
		{
			return FALSE;
		}

		if (DWORD dwCodeIntegrityLevel = 0;
			hToken && GetTokenIntegrityLevel(hToken, &dwCodeIntegrityLevel))
		{
			// 目前发现 chrome 的沙箱进程貌似有完整性检查
			if (dwCodeIntegrityLevel == SECURITY_MANDATORY_LOW_RID || dwCodeIntegrityLevel == SECURITY_MANDATORY_UNTRUSTED_RID)
			{
				return TRUE;
			}
		}
		const BOOL bRet = inject_dll_to_process(lpProcessInformation);
		if (bRet)
		{
			if (!bOrigSuspended)
			{
				ResumeThread(lpProcessInformation->hThread);
			}
			if (lpProcessInformation == &backup)
			{
				CloseHandle(lpProcessInformation->hProcess);
				CloseHandle(lpProcessInformation->hThread);
			}
		}
		else
		{
			TerminateProcess(lpProcessInformation->hProcess, ~0u);
			CloseHandle(lpProcessInformation->hProcess);
			CloseHandle(lpProcessInformation->hThread);
			if (lpProcessInformation != &backup)
			{
				lpProcessInformation->hProcess = nullptr;
				lpProcessInformation->hThread = nullptr;
				lpProcessInformation->dwProcessId = 0;
				lpProcessInformation->dwThreadId = 0;
			}
		}
		return bRet;
	}

	template <auto Trampoline>
	BOOL WINAPI CreateProcessAsUserW(_In_opt_ HANDLE hToken, _In_opt_ LPCWSTR lpApplicationName, _Inout_opt_ LPWSTR lpCommandLine,
	                                 _In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes, _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes, _In_ BOOL bInheritHandles,
	                                 _In_ DWORD dwCreationFlags, _In_opt_ LPVOID lpEnvironment, _In_opt_ LPCWSTR lpCurrentDirectory,
	                                 _In_ LPSTARTUPINFOW lpStartupInfo, _Out_ LPPROCESS_INFORMATION lpProcessInformation)
	{
		const BOOL bOrigSuspended = dwCreationFlags & CREATE_SUSPENDED;
		if (!bOrigSuspended)
		{
			dwCreationFlags |= CREATE_SUSPENDED;
		}

		PROCESS_INFORMATION backup{};
		if (!lpProcessInformation)
		{
			lpProcessInformation = &backup;
		}

		if (!Trampoline(hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles,
		                dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation))
		{
			return FALSE;
		}

		if (DWORD dwCodeIntegrityLevel = 0;
			hToken && GetTokenIntegrityLevel(hToken, &dwCodeIntegrityLevel))
		{
			// 目前发现 chrome 的沙箱进程貌似有完整性检查
			if (dwCodeIntegrityLevel == SECURITY_MANDATORY_LOW_RID || dwCodeIntegrityLevel == SECURITY_MANDATORY_UNTRUSTED_RID)
			{
				return TRUE;
			}
		}
		const BOOL bRet = inject_dll_to_process(lpProcessInformation);
		if (bRet)
		{
			if (!bOrigSuspended)
			{
				ResumeThread(lpProcessInformation->hThread);
			}
			if (lpProcessInformation == &backup)
			{
				CloseHandle(lpProcessInformation->hProcess);
				CloseHandle(lpProcessInformation->hThread);
			}
		}
		else
		{
			TerminateProcess(lpProcessInformation->hProcess, ~0u);
			CloseHandle(lpProcessInformation->hProcess);
			CloseHandle(lpProcessInformation->hThread);
			if (lpProcessInformation != &backup)
			{
				lpProcessInformation->hProcess = nullptr;
				lpProcessInformation->hThread = nullptr;
				lpProcessInformation->dwProcessId = 0;
				lpProcessInformation->dwThreadId = 0;
			}
		}
		return bRet;
	}

	template <auto Trampoline>
	BOOL WINAPI CreateProcessWithLogonW(_In_ LPCWSTR lpUsername, _In_opt_ LPCWSTR lpDomain, _In_ LPCWSTR lpPassword,
	                                    _In_ DWORD dwLogonFlags, _In_opt_ LPCWSTR lpApplicationName, _Inout_opt_ LPWSTR lpCommandLine,
	                                    _In_ DWORD dwCreationFlags, _In_opt_ LPVOID lpEnvironment, _In_opt_ LPCWSTR lpCurrentDirectory,
	                                    _In_ LPSTARTUPINFOW lpStartupInfo, _Out_ LPPROCESS_INFORMATION lpProcessInformation)
	{
		const BOOL bOrigSuspended = dwCreationFlags & CREATE_SUSPENDED;
		if (!bOrigSuspended)
		{
			dwCreationFlags |= CREATE_SUSPENDED;
		}

		PROCESS_INFORMATION backup{};
		if (!lpProcessInformation)
		{
			lpProcessInformation = &backup;
		}

		if (!Trampoline(lpUsername, lpDomain, lpPassword, dwLogonFlags, lpApplicationName, lpCommandLine, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation))
		{
			return FALSE;
		}

		if (DWORD dwCodeIntegrityLevel = 0;
			GetProcessIntegrityLevel(lpProcessInformation->hProcess, &dwCodeIntegrityLevel))
		{
			if (dwCodeIntegrityLevel == SECURITY_MANDATORY_LOW_RID || dwCodeIntegrityLevel == SECURITY_MANDATORY_UNTRUSTED_RID)
			{
				return TRUE;
			}
		}
		const BOOL bRet = inject_dll_to_process(lpProcessInformation);
		if (bRet)
		{
			if (!bOrigSuspended)
			{
				ResumeThread(lpProcessInformation->hThread);
			}
			if (lpProcessInformation == &backup)
			{
				CloseHandle(lpProcessInformation->hProcess);
				CloseHandle(lpProcessInformation->hThread);
			}
		}
		else
		{
			TerminateProcess(lpProcessInformation->hProcess, ~0u);
			CloseHandle(lpProcessInformation->hProcess);
			CloseHandle(lpProcessInformation->hThread);
			if (lpProcessInformation != &backup)
			{
				lpProcessInformation->hProcess = nullptr;
				lpProcessInformation->hThread = nullptr;
				lpProcessInformation->dwProcessId = 0;
				lpProcessInformation->dwThreadId = 0;
			}
		}
		return bRet;
	}

	template <auto Trampoline>
	BOOL WINAPI CreateProcessWithTokenW(_In_ HANDLE hToken, _In_ DWORD dwLogonFlags,
	                                    _In_opt_ LPCWSTR lpApplicationName, _Inout_opt_ LPWSTR lpCommandLine, _In_ DWORD dwCreationFlags,
	                                    _In_opt_ LPVOID lpEnvironment, _In_opt_ LPCWSTR lpCurrentDirectory,
	                                    _In_ LPSTARTUPINFOW lpStartupInfo, _Out_ LPPROCESS_INFORMATION lpProcessInformation)
	{
		const BOOL bOrigSuspended = dwCreationFlags & CREATE_SUSPENDED;
		if (!bOrigSuspended)
		{
			dwCreationFlags |= CREATE_SUSPENDED;
		}

		PROCESS_INFORMATION backup{};
		if (!lpProcessInformation)
		{
			lpProcessInformation = &backup;
		}

		if (!Trampoline(hToken, dwLogonFlags, lpApplicationName, lpCommandLine, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation))
		{
			return FALSE;
		}

		if (DWORD dwCodeIntegrityLevel = 0;
			hToken && GetTokenIntegrityLevel(hToken, &dwCodeIntegrityLevel))
		{
			if (dwCodeIntegrityLevel == SECURITY_MANDATORY_LOW_RID || dwCodeIntegrityLevel == SECURITY_MANDATORY_UNTRUSTED_RID)
			{
				return TRUE;
			}
		}
		const BOOL bRet = inject_dll_to_process(lpProcessInformation);
		if (bRet)
		{
			if (!bOrigSuspended)
			{
				ResumeThread(lpProcessInformation->hThread);
			}
			if (lpProcessInformation == &backup)
			{
				CloseHandle(lpProcessInformation->hProcess);
				CloseHandle(lpProcessInformation->hThread);
			}
		}
		else
		{
			TerminateProcess(lpProcessInformation->hProcess, ~0u);
			CloseHandle(lpProcessInformation->hProcess);
			CloseHandle(lpProcessInformation->hThread);
			if (lpProcessInformation != &backup)
			{
				lpProcessInformation->hProcess = nullptr;
				lpProcessInformation->hThread = nullptr;
				lpProcessInformation->dwProcessId = 0;
				lpProcessInformation->dwThreadId = 0;
			}
		}
		return bRet;
	}

	// MachineGuid has no stable registry path across views (native / Wow6432Node), so it is recognised by value
	// name plus GUID shape rather than by key. A different key that also holds a GUID named "MachineGuid" is
	// rewritten too; this only happens inside a process that was started with the `os` capability.
	bool is_machine_guid_name(const wchar_t* name)
	{
		static constexpr std::wstring_view expected = L"MachineGuid";
		if (!name) return false;
		for (std::size_t i = 0; i < expected.size(); ++i)
		{
			if (std::towlower(name[i]) != std::towlower(expected[i])) return false;
		}
		return name[expected.size()] == L'\0';
	}

	void rewrite_machine_guid_value(const wchar_t* name, DWORD type, void* data, DWORD bytes)
	{
		if (!data || type != REG_SZ || !is_machine_guid_name(name)) return;
		const DWORD chars = bytes / sizeof(wchar_t);
		if (chars < 36 || chars > 39) return; // 36 characters, optional braces and terminator
		auto* text = static_cast<wchar_t*>(data);
		std::string ascii;
		for (DWORD i = 0; i < chars && text[i] != L'\0'; ++i)
		{
			if (text[i] > 127) return;
			ascii.push_back(static_cast<char>(text[i]));
		}
		const std::string replaced = global::Data::get().virtualMachineGuid(ascii);
		if (replaced.size() != ascii.size() || replaced == ascii) return;
		for (std::size_t i = 0; i < replaced.size(); ++i) text[i] = static_cast<wchar_t>(replaced[i]);
	}

	template <auto Trampoline>
	LSTATUS WINAPI RegQueryValueExW(HKEY key, LPCWSTR valueName, LPDWORD reserved, LPDWORD type, LPBYTE data, LPDWORD size)
	{
		DWORD localType = 0;
		const LSTATUS status = Trampoline(key, valueName, reserved, type ? type : &localType, data, size);
		if (status == ERROR_SUCCESS && data && size)
		{
			rewrite_machine_guid_value(valueName, type ? *type : localType, data, *size);
		}
		return status;
	}

	template <auto Trampoline>
	LSTATUS WINAPI RegGetValueW(HKEY key, LPCWSTR subKey, LPCWSTR valueName, DWORD flags, LPDWORD type, PVOID data, LPDWORD size)
	{
		DWORD localType = 0;
		const LSTATUS status = Trampoline(key, subKey, valueName, flags, type ? type : &localType, data, size);
		if (status == ERROR_SUCCESS && data && size)
		{
			rewrite_machine_guid_value(valueName, type ? *type : localType, data, *size);
		}
		return status;
	}

	// Registry identity (capability `os`). Independent of isolation, so it is installed on its own.
	void hook_registry_identity()
	{
		create_hook_by_func_ptr<&::RegQueryValueExW>().setHookFromGetter([&](auto trampolineConst)
		{
			return HookInfo{&RegQueryValueExW<trampolineConst.value>};
		});
		create_hook_by_func_ptr<&::RegGetValueW>().setHookFromGetter([&](auto trampolineConst)
		{
			return HookInfo{&RegGetValueW<trampolineConst.value>};
		});
	}

	void hook_advapi32()
	{
		// win7 or earlier
		if (!global::Data::get().sysVersion().isWindows8OrGreater)
		{
			create_hook_by_func_ptr<&::RegLoadAppKeyW>().setHook(&RegLoadAppKeyW);
		}

		create_hook_by_func_ptr<&::CreateProcessAsUserA>().setHookFromGetter([&](auto trampolineConst)
		{
			return HookInfo{&CreateProcessAsUserA<trampolineConst.value>};
		});
		create_hook_by_func_ptr<&::CreateProcessAsUserW>().setHookFromGetter([&](auto trampolineConst)
		{
			return HookInfo{&CreateProcessAsUserW<trampolineConst.value>};
		});
		create_hook_by_func_ptr<&::CreateProcessWithLogonW>().setHookFromGetter([&](auto trampolineConst)
		{
			return HookInfo{&CreateProcessWithLogonW<trampolineConst.value>};
		});
		create_hook_by_func_ptr<&::CreateProcessWithTokenW>().setHookFromGetter([&](auto trampolineConst)
		{
			return HookInfo{&CreateProcessWithTokenW<trampolineConst.value>};
		});
	}
}
