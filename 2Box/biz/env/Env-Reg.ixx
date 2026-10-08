export module Env:Reg;

import "sys_defs.h";
import std;
import :Envrironment;

namespace biz
{
	class RegKey
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

	struct EnvInitializeData
	{
		std::uint32_t index;
		std::uint64_t flag;
		std::wstring_view flagName;
		std::wstring_view name;
		std::uint64_t deviceProfileId{0}; // 0: no device profile bound
	};

	using EnvInitializeNotify = std::function<void(const EnvInitializeData&)>;

	export void initialize_env_reg(const EnvInitializeNotify& notify);
	export void add_env_to_reg(std::wstring_view flagName, const Env* env);
	export void delete_env_from_reg(std::wstring_view flagName);
	// Bind (or with 0, unbind) a device profile to an environment. The profile itself lives in a file; see DeviceProfile.hpp.
	export void set_env_device_profile(std::wstring_view flagName, std::uint64_t profileId);
}
