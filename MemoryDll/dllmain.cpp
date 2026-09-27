#ifdef REFLECTIVE_INJECT
#ifndef _WIN64
#pragma comment(linker, "/EXPORT:initialize=_initialize@4")
#endif
#endif

import "sys_defs.h";
import std;

#include "biz_initializer.h"

#ifndef REFLECTIVE_INJECT
namespace
{
	using ProcessEntry = int (WINAPI*)();
	ProcessEntry originalProcessEntry = nullptr;
	DetourInjectParams* pendingParams = nullptr;

	int WINAPI managed_process_entry()
	{
		DetourInjectParams* params = std::exchange(pendingParams, nullptr);
		if (!params) TerminateProcess(GetCurrentProcess(), 1);
		biz_initialize(params->version, params->envFlag, params->envIndex,
			params->rootPath, params->rootPathCount);
		std::free(params);
		return originalProcessEntry();
	}
}
#endif

#ifdef REFLECTIVE_INJECT
extern "C" __declspec(dllexport) unsigned long __stdcall initialize(void* lpThreadParameter)
{
	if (!lpThreadParameter)
	{
		TerminateProcess(GetCurrentProcess(), 1);
	}

	const ReflectiveInjectParams& injectParams = *static_cast<ReflectiveInjectParams*>(lpThreadParameter);
	const EssentialData& essentialData = injectParams.essentialData;
	const char* pThisModuleAddress = reinterpret_cast<const char*>(injectParams.injectionInfo.dllAddress);
	const pe::MemoryModule thisModule{pe::Parser<pe::parser_flag::HasSectionAligned>{pThisModuleAddress}};

	pe::fill_os_version(essentialData.version);
	pe::fill_all_symbols(essentialData.symRva32, essentialData.symRva64);

	pe::set_section_protection(thisModule);
	pe::enable_exceptions(thisModule);
	if (!pe::init_static_tls(thisModule))
	{
		TerminateProcess(GetCurrentProcess(), 1);
	}
	pe::wipe_header_memory(thisModule);

	biz_initialize(injectParams.envFlag, injectParams.envIndex, injectParams.rootPath, injectParams.rootPathCount);
	return 0;
}
#endif

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID /*lpReserved*/)
{
#ifndef REFLECTIVE_INJECT
	if (DetourIsHelperProcess())
	{
		return TRUE;
	}
	if (DLL_PROCESS_ATTACH == ul_reason_for_call)
	{
		DetourRestoreAfterWith();
		DisableThreadLibraryCalls(hModule);
		DWORD payloadSize = 0;
		void* payload = DetourFindPayloadEx(DETOUR_INJECT_PARAMS_GUID, &payloadSize);
		if (!payload || payloadSize < sizeof(DetourInjectParams))
		{
			TerminateProcess(GetCurrentProcess(), 1);
		}
		const DetourInjectParams& injectParams = *static_cast<DetourInjectParams*>(payload);
		if (injectParams.rootPathCount > (payloadSize - sizeof(DetourInjectParams)) / sizeof(wchar_t))
		{
			TerminateProcess(GetCurrentProcess(), 1);
		}
		pendingParams = static_cast<DetourInjectParams*>(std::malloc(payloadSize));
		if (!pendingParams)
		{
			TerminateProcess(GetCurrentProcess(), 1);
		}
		std::memcpy(pendingParams, payload, payloadSize);
		DetourFreePayload(payload);
		originalProcessEntry = reinterpret_cast<ProcessEntry>(DetourGetEntryPoint(GetModuleHandleW(nullptr)));
		if (!originalProcessEntry || DetourTransactionBegin() != NO_ERROR
			|| DetourUpdateThread(GetCurrentThread()) != NO_ERROR
			|| DetourAttach(reinterpret_cast<void**>(&originalProcessEntry),
				reinterpret_cast<void*>(&managed_process_entry)) != NO_ERROR
			|| DetourTransactionCommit() != NO_ERROR)
		{
			TerminateProcess(GetCurrentProcess(), 1);
		}
	}
#endif
	return TRUE;
}
