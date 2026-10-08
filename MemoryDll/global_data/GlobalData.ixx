module;
#include "DeviceIdentityProvider.hpp"
#include "DeviceLaunch.hpp"
#include "InstanceIdentity.hpp"
export module GlobalData;

import "sys_defs.h";
import std;

namespace global
{
	export class RegKey
	{
	public:
		RegKey() = default;

		explicit RegKey(auto creator)
		{
			m_key = creator();
		}

		~RegKey()
		{
			if (m_key)
			{
				RegCloseKey(m_key);
			}
		}

		RegKey(const RegKey&) = delete;
		RegKey& operator=(const RegKey&) = delete;

		RegKey(RegKey&& that) noexcept : m_key(std::exchange(that.m_key, nullptr))
		{
		}

		RegKey& operator=(RegKey&& that) noexcept
		{
			std::swap(m_key, that.m_key);
			return *this;
		}

		operator HKEY() const { return m_key; }

	private:
		HKEY m_key{nullptr};
	};

	export class Data
	{
	public:
		static Data& get()
		{
			static Data instance;
			return instance;
		}

	public:
		// `launchConfigText` is the encoded form of `launchConfig`; it is forwarded unchanged to child processes.
		void initialize(SystemVersionInfo versionInfo, const devid::InstanceIdentity& instance, std::wstring_view rootPath,
		                devid::LaunchConfig launchConfig, std::string launchConfigText);

	public:
		SystemVersionInfo sysVersion() const { return m_sysVersion; }
		bool isNonLimitedAdmin() const { return m_bIsNonLimitedAdmin; }
		std::wstring_view rootPath() const { return m_rootPath; }
		std::string_view dllFullPath() const { return m_dllFullPath; }
		HKEY appKey() const { return m_appKey; }
		std::uint32_t inputSyncMsgId() const { return m_inputSyncMsgId; }

		// Instance identity: which isolated instance this is. It never influences device answers.
		const devid::InstanceIdentity& instance() const { return m_instance; }
		std::uint64_t envFlag() const { return m_instance.instanceId; } // RPC identity
		std::uint32_t envIndex() const { return m_instance.instanceIndex; }
		std::wstring_view objectNamespaceName() const { return m_objectNamespaceName; }
		std::string_view objectNamespaceNameA() const { return m_objectNamespaceNameA; }
		std::wstring_view registrySuffixName() const { return m_registrySuffixName; }

		// Launch configuration decided by the host: which hooks are installed and whether a device profile is active.
		const devid::HookPlan& hookPlan() const { return m_hookPlan; }
		std::string_view launchConfigText() const { return m_launchConfigText; }
		bool storageSimulated() const { return m_device && m_hookPlan.storage; }
		bool networkSimulated() const { return m_device && m_hookPlan.network; }
		bool smbiosSimulated() const { return m_device && m_hookPlan.smbios; }
		bool osSimulated() const { return m_device && m_hookPlan.os; }

		// Device identity: answers come from the device profile only. Without a profile every call is a no-op.
		std::string virtualDiskSerial(std::string_view serial, bool ataWordOrder = false) const;
		std::string virtualSystemSerial(std::string_view serial) const;
		std::string virtualBoardSerial(std::string_view serial) const;
		std::string virtualChassisSerial(std::string_view serial) const;
		std::string virtualPnpInstance(bool network, std::string_view suffix) const;
		std::string virtualAdapterGuid(std::string_view guid) const;
		std::string virtualSystemUuid(std::string_view uuid) const;
		std::string virtualMachineGuid(std::string_view guid) const;
		void virtualMac(std::uint8_t* address, std::size_t length) const;
		void rewriteSmbiosTable(std::uint8_t* table, std::size_t size) const;

		bool isInKnownFolderPath(std::wstring_view path) const;
		std::optional<std::wstring> getRedirectPath(std::wstring_view knownFolderPath) const;

	private:
		Data() = default;

		void initializePrivilegesAbout();
		void initializeRegistry();
		void initializeDllFullPath();
		void initializeKnownFolderPath();
		void initializeMisc();

	private:
		SystemVersionInfo m_sysVersion;
		devid::InstanceIdentity m_instance;
		bool m_bIsNonLimitedAdmin{false};
		std::wstring m_objectNamespaceName;
		std::string m_objectNamespaceNameA;
		std::wstring m_registrySuffixName;
		std::string m_dllFullPath;
		std::wstring m_rootPath;
		RegKey m_appKey;
		std::vector<std::wstring> m_knownFolders;
		std::uint32_t m_inputSyncMsgId{0};
		devid::HookPlan m_hookPlan;
		std::string m_launchConfigText;
		std::unique_ptr<devid::DeviceIdentityProvider> m_device;
	};

	export bool is_app_key_name(std::wstring_view fullName)
	{
		static constexpr std::wstring_view prefixToFind(LR"(\REGISTRY\A\{)");
		return fullName.starts_with(prefixToFind);
	}

	export std::wstring_view remove_leading_backslashes_sv(std::wstring_view sv)
	{
		const auto it = std::find_if_not(sv.begin(), sv.end(), [](wchar_t c) { return c == L'\\'; });
		if (it == sv.end())
		{
			return sv;
		}
		return sv.substr(std::distance(sv.begin(), it));
	}

	export bool ensure_dir_exists(std::wstring_view fullName, bool bIsDir);
}
