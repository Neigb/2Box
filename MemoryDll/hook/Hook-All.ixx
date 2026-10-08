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
import GlobalData;

namespace hook
{
	// The hook set is a pure function of the launch plan the host injected (DeviceLaunch.hpp):
	// isolation hooks give plain multi-instance behaviour, every device capability is opt-in.
	export void hook_all()
	{
		const auto& plan = global::Data::get().hookPlan();
		if (plan.isolation) hook_ntdll();
		hook_kernel32(plan.isolation, plan.storage, plan.storageAsync, plan.storageWait, plan.smbios);
		if (plan.isolation)
		{
			hook_advapi32();
			hook_shell32();
			hook_user32();
		}
		if (plan.os) hook_registry_identity();
		if (plan.wmi) hook_ole32();
		if (plan.network)
		{
			hook_iphlpapi();
			hook_netapi32();
		}

		HookManager::instance().installAll();
	}
}
