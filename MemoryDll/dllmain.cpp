
import "sys_defs.h";
import std;

#include "biz_initializer.h"
#include "probe_trace.h"

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
		biz_initialize(params);
		probe_trace("initialized");
		std::free(params);
		if (const LONG error = DetourTransactionBegin(); error != NO_ERROR)
		{
			probe_trace("entry detach transaction begin failed", error);
			TerminateProcess(GetCurrentProcess(), 1);
		}
		if (const LONG error = DetourUpdateThread(GetCurrentThread()); error != NO_ERROR)
		{
			DetourTransactionAbort();
			probe_trace("entry detach update thread failed", error);
			TerminateProcess(GetCurrentProcess(), 1);
		}
		if (const LONG error = DetourDetach(reinterpret_cast<void**>(&originalProcessEntry),
			reinterpret_cast<void*>(&managed_process_entry)); error != NO_ERROR)
		{
			DetourTransactionAbort();
			probe_trace("entry detach failed", error);
			TerminateProcess(GetCurrentProcess(), 1);
		}
		if (const LONG error = DetourTransactionCommit(); error != NO_ERROR)
		{
			probe_trace("entry detach commit failed", error);
			TerminateProcess(GetCurrentProcess(), 1);
		}
		probe_trace("entry detour detached");
		return originalProcessEntry();
	}
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID /*lpReserved*/)
{
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
		if (!payload || payloadSize < FIELD_OFFSET(DetourInjectParams, rootPath))
		{
			probe_trace("missing detours payload", payloadSize);
			TerminateProcess(GetCurrentProcess(), 1);
		}
		const DetourInjectParams& injectParams = *static_cast<DetourInjectParams*>(payload);
		const DWORD tailBytes = payloadSize - FIELD_OFFSET(DetourInjectParams, rootPath);
		if (injectParams.rootPathCount > tailBytes / sizeof(wchar_t)
			|| injectParams.launchConfigBytes != tailBytes - injectParams.rootPathCount * sizeof(wchar_t))
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
	return TRUE;
}
