#ifdef REFLECTIVE_INJECT
#ifndef _WIN64
#pragma comment(linker, "/EXPORT:initialize=_initialize@4")
#endif
#endif

import "sys_defs.h";
import std;

#include "biz_initializer.h"
#include "probe_trace.h"

#ifndef REFLECTIVE_INJECT
namespace
{
	using ProcessEntry = int (WINAPI*)();
	ProcessEntry originalProcessEntry = nullptr;
	DetourInjectParams* pendingParams = nullptr;

	int WINAPI managed_process_entry()
	{
		probe_trace("entry");
		DetourInjectParams* params = std::exchange(pendingParams, nullptr);
		if (!params)
		{
			probe_trace("missing copied payload");
			TerminateProcess(GetCurrentProcess(), 1);
		}
		biz_initialize(params->version, params->envFlag, params->envIndex,
			params->rootPath, params->rootPathCount);
		probe_trace("initialized");
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
		probe_trace("dll attached");
		DWORD payloadSize = 0;
		void* payload = DetourFindPayloadEx(DETOUR_INJECT_PARAMS_GUID, &payloadSize);
		if (!payload || payloadSize < sizeof(DetourInjectParams))
		{
			probe_trace("missing detours payload", payloadSize);
			TerminateProcess(GetCurrentProcess(), 1);
		}
		const DetourInjectParams& injectParams = *static_cast<DetourInjectParams*>(payload);
		if (injectParams.rootPathCount > (payloadSize - sizeof(DetourInjectParams)) / sizeof(wchar_t))
		{
			probe_trace("invalid payload length", injectParams.rootPathCount);
			TerminateProcess(GetCurrentProcess(), 1);
		}
		pendingParams = static_cast<DetourInjectParams*>(std::malloc(payloadSize));
		if (!pendingParams)
		{
			probe_trace("payload allocation failed", payloadSize);
			TerminateProcess(GetCurrentProcess(), 1);
		}
		std::memcpy(pendingParams, payload, payloadSize);
		DetourFreePayload(payload);
		originalProcessEntry = reinterpret_cast<ProcessEntry>(DetourGetEntryPoint(GetModuleHandleW(nullptr)));
		if (!originalProcessEntry)
		{
			probe_trace("entrypoint unavailable");
			TerminateProcess(GetCurrentProcess(), 1);
		}
		if (const LONG error = DetourTransactionBegin(); error != NO_ERROR)
		{
			probe_trace("entry transaction begin failed", error);
			TerminateProcess(GetCurrentProcess(), 1);
		}
		if (const LONG error = DetourUpdateThread(GetCurrentThread()); error != NO_ERROR)
		{
			DetourTransactionAbort();
			probe_trace("entry update thread failed", error);
			TerminateProcess(GetCurrentProcess(), 1);
		}
		if (const LONG error = DetourAttach(reinterpret_cast<void**>(&originalProcessEntry),
			reinterpret_cast<void*>(&managed_process_entry)); error != NO_ERROR)
		{
			DetourTransactionAbort();
			probe_trace("entry attach failed", error);
			TerminateProcess(GetCurrentProcess(), 1);
		}
		if (const LONG error = DetourTransactionCommit(); error != NO_ERROR)
		{
			probe_trace("entry commit failed", error);
			TerminateProcess(GetCurrentProcess(), 1);
		}
		probe_trace("entry detour attached");
	}
#endif
	return TRUE;
}
