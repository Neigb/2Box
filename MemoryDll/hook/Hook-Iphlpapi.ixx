export module Hook:Iphlpapi;

import "sys_defs.h";
import std;
import :Core;
import GlobalData;

namespace hook
{
	void rewrite_adapter_name(char* name)
	{
		if (!name) return;
		const std::string_view source{name};
		const std::size_t brace = source.find('{');
		const std::size_t start = brace == std::string_view::npos ? 0 : brace;
		const std::size_t length = brace == std::string_view::npos ? 36 : 38;
		if (source.size() - start < length) return;
		const std::string_view guid = source.substr(start, length);
		if (brace != std::string_view::npos && guid.back() != '}') return;
		const std::string value = global::Data::get().virtualAdapterGuid(guid);
		if (value.size() == guid.size()) std::memcpy(name + start, value.data(), value.size());
	}

	template <auto Trampoline>
	ULONG WINAPI GetAdaptersInfo(_Out_writes_bytes_opt_(*SizePointer) PIP_ADAPTER_INFO AdapterInfo, _Inout_ PULONG SizePointer)
	{
		const ULONG result = Trampoline(AdapterInfo, SizePointer);
		const DWORD error = GetLastError();
		if (result == ERROR_SUCCESS)
		{
			PIP_ADAPTER_INFO pCurrAddresses = AdapterInfo;
			while (pCurrAddresses)
			{
				rewrite_adapter_name(pCurrAddresses->AdapterName);
				global::Data::get().virtualMac(pCurrAddresses->Address, pCurrAddresses->AddressLength);

				pCurrAddresses = pCurrAddresses->Next;
			}
		}
		SetLastError(error);
		return result;
	}

	template <auto Trampoline>
	ULONG WINAPI GetAdaptersAddresses(_In_ ULONG Family, _In_ ULONG Flags, _Reserved_ PVOID Reserved,
	                                  _Out_writes_bytes_opt_(*SizePointer) PIP_ADAPTER_ADDRESSES AdapterAddresses, _Inout_ PULONG SizePointer)
	{
		const ULONG result = Trampoline(Family, Flags, Reserved, AdapterAddresses, SizePointer);
		const DWORD error = GetLastError();
		if (result == ERROR_SUCCESS)
		{
			PIP_ADAPTER_ADDRESSES pCurrAddresses = AdapterAddresses;
			while (pCurrAddresses)
			{
				rewrite_adapter_name(pCurrAddresses->AdapterName);
				global::Data::get().virtualMac(pCurrAddresses->PhysicalAddress, pCurrAddresses->PhysicalAddressLength);

				pCurrAddresses = pCurrAddresses->Next;
			}
		}
		SetLastError(error);
		return result;
	}

	void hook_iphlpapi()
	{
		constexpr auto IPHLPAPI_LIB_NAME = utils::make_literal_name<L"iphlpapi.dll">();

		create_hook_by_func_type<IPHLPAPI_LIB_NAME, utils::make_literal_name<"GetAdaptersInfo">(), decltype(::GetAdaptersInfo)>().setHookFromGetter([&](auto trampolineConst)
		{
			return HookInfo{&GetAdaptersInfo<trampolineConst.value>};
		});
		create_hook_by_func_type<IPHLPAPI_LIB_NAME, utils::make_literal_name<"GetAdaptersAddresses">(), decltype(::GetAdaptersAddresses)>().setHookFromGetter([&](auto trampolineConst)
		{
			return HookInfo{&GetAdaptersAddresses<trampolineConst.value>};
		});
	}
}
