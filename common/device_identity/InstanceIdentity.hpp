#pragma once

// Instance identity: which isolated instance a process belongs to.
// It intentionally knows nothing about device identity (see DeviceProfile.hpp).
// Numeric values are the legacy envFlag/envIndex so existing environments need no migration,
// but every role that used to share envFlag now has its own accessor and can diverge later.

#include <cstdint>
#include <string>

namespace devid
{
	namespace detail
	{
		inline std::string hex16(std::uint64_t value)
		{
			static constexpr char digits[] = "0123456789ABCDEF";
			std::string result(16, '0');
			for (int i = 15; i >= 0; --i)
			{
				result[static_cast<std::size_t>(i)] = digits[value & 0xF];
				value >>= 4;
			}
			return result;
		}
	}

	struct InstanceIdentity
	{
		std::uint64_t instanceId{0};
		std::uint32_t instanceIndex{0};
		// Random per host run; identifies one launch generation, never persisted.
		std::uint64_t sessionId{0};
		// Suffix appended to NT object / pipe names. Defaults to instanceId for compatibility.
		std::uint64_t objectNamespaceId{0};

		static InstanceIdentity fromLegacy(std::uint64_t envFlag, std::uint32_t envIndex, std::uint64_t sessionId = 0)
		{
			return InstanceIdentity{envFlag, envIndex, sessionId, envFlag};
		}

		// Injected DLL file stem: bin/<dllStem>_64.bin
		std::string dllStem() const { return detail::hex16(instanceId); }
		// Per-instance registry hive file and virtual registry sub-key suffix.
		std::string hiveName() const { return detail::hex16(instanceId); }
		std::string registrySuffix() const { return detail::hex16(instanceId); }
		// NT named-object / named-pipe / boundary-descriptor suffix.
		std::string objectNamespaceSuffix() const { return detail::hex16(objectNamespaceId); }
	};
}
