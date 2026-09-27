export module Hook:Iphlpapi;

import "sys_defs.h";
import std;
import :Core;
import GlobalData;

namespace hook
{
	template <auto Trampoline>
	ULONG WINAPI GetAdaptersInfo(_Out_writes_bytes_opt_(*SizePointer) PIP_ADAPTER_INFO AdapterInfo, _Inout_ PULONG SizePointer)
	{
		const ULONG result = Trampoline(AdapterInfo, SizePointer);
		if (result == ERROR_SUCCESS)
		{
			PIP_ADAPTER_INFO pCurrAddresses = AdapterInfo;
			while (pCurrAddresses)
			{
				global::Data::get().virtualMac(pCurrAddresses->Address, pCurrAddresses->AddressLength);

				pCurrAddresses = pCurrAddresses->Next;
			}
		}
		return result;
	}

	template <auto Trampoline>
	ULONG WINAPI GetAdaptersAddresses(_In_ ULONG Family, _In_ ULONG Flags, _Reserved_ PVOID Reserved,
	                                  _Out_writes_bytes_opt_(*SizePointer) PIP_ADAPTER_ADDRESSES AdapterAddresses, _Inout_ PULONG SizePointer)
	{
		const ULONG result = Trampoline(Family, Flags, Reserved, AdapterAddresses, SizePointer);
		if (result == ERROR_SUCCESS)
		{
			PIP_ADAPTER_ADDRESSES pCurrAddresses = AdapterAddresses;
			while (pCurrAddresses)
			{
				global::Data::get().virtualMac(pCurrAddresses->PhysicalAddress, pCurrAddresses->PhysicalAddressLength);

				pCurrAddresses = pCurrAddresses->Next;
			}
		}
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
