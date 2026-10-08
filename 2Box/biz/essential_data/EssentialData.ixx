module;
#include "res/resource.h"
export module EssentialData;

import "sys_defs.h";
import std;

namespace biz
{
	export struct DllResourceInfo
	{
		char* address;
		unsigned int size;
	};

	export struct CoreData
	{
		SystemVersionInfo version;
		DllResourceInfo dll32;
		DllResourceInfo dll64;
	};

	inline CoreData g_core_data;

	namespace detail
	{
		template <ArchBit BitType = CURRENT_ARCH_BIT>
		DllResourceInfo get_dll_resource()
		{
			HRSRC hRes;
			if constexpr (BitType == ArchBit::Bit32)
			{
				hRes = FindResourceW(nullptr, MAKEINTRESOURCEW(IDR_MEM_DLL_32), RT_RCDATA);
			}
			else
			{
				hRes = FindResourceW(nullptr, MAKEINTRESOURCEW(IDR_MEM_DLL_64), RT_RCDATA);
			}
			if (!hRes)
			{
				throw std::runtime_error("failed to find resource");
			}

			const HGLOBAL hResourceLoaded = LoadResource(nullptr, hRes);
			if (!hResourceLoaded)
			{
				throw std::runtime_error("failed to load resource");
			}

			return {
				static_cast<char*>(LockResource(hResourceLoaded)),
				SizeofResource(nullptr, hRes)
			};
		}
	}

	export void init_system_version_info()
	{
		SystemVersionInfo& version = g_core_data.version;
		version.isWindows8Point1OrGreater = IsWindows8Point1OrGreater();
		version.isWindows8OrGreater = IsWindows8OrGreater();
		version.isWindowsVistaOrGreater = IsWindowsVistaOrGreater();

		SYSTEM_INFO sysInfo{};
		GetNativeSystemInfo(&sysInfo);
		version.is32BitSystem = sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL || sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM;
	}

	export void init_resource_info()
	{
		g_core_data.dll32 = detail::get_dll_resource<ArchBit::Bit32>();
		g_core_data.dll64 = detail::get_dll_resource<ArchBit::Bit64>();
	}

	export const CoreData& get_core_data() noexcept { return g_core_data; }
}
