// ReSharper disable CppUseRangeAlgorithm
module;
// #define _CRT_SECURE_NO_WARNINGS
// #include <cstdio>
module GlobalData;

import "sys_defs.h";
#ifndef _SYS_DEFS_H_
#pragma message("Just for IntelliSense. You should not see this message!")
import "sys_defs.hpp";
#endif

namespace
{
	std::uint64_t hash_identity(std::uint64_t seed, std::string_view source)
	{
		std::uint64_t hash = 14695981039346656037ULL ^ seed;
		for (const unsigned char c : source)
		{
			hash = (hash ^ c) * 1099511628211ULL;
		}
		return hash;
	}

	std::string normalize_disk_serial(std::string_view raw, bool ataWordOrder)
	{
		std::string value{raw};
		if (ataWordOrder)
		{
			for (std::size_t i = 0; i + 1 < value.size(); i += 2)
			{
				std::swap(value[i], value[i + 1]);
			}
		}
		const auto isPadding = [](char c) { return c == '\0' || c == ' ' || c == '\t'; };
		while (!value.empty() && isPadding(value.front())) value.erase(value.begin());
		while (!value.empty() && isPadding(value.back())) value.pop_back();
		for (char& c : value)
		{
			if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 'a' + 'A');
		}
		return value;
	}

	// void InitConsole()
	// {
	// 	if (!AllocConsole())
	// 	{
	// 		return;
	// 	}
	//
	// 	freopen("CONOUT$", "w", stdout);
	// }

	BOOL get_process_elevation(TOKEN_ELEVATION_TYPE* pElevationType, BOOL* pIsAdmin)
	{
		HANDLE hToken{nullptr};
		DWORD dwSize;

		// Get current process token
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
		{
			return FALSE;
		}

		BOOL bResult = FALSE;
		// Retrieve elevation type information 
		if (GetTokenInformation(hToken, TokenElevationType,
		                        pElevationType, sizeof(TOKEN_ELEVATION_TYPE), &dwSize))
		{
			// Create the SID corresponding to the Administrators group
			byte adminSid[SECURITY_MAX_SID_SIZE]{};
			dwSize = sizeof(adminSid);
			CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, &adminSid, &dwSize);

			if (*pElevationType == TokenElevationTypeLimited)
			{
				// Get handle to linked token (will have one if we are lua)
				HANDLE hUnfilteredToken{nullptr};
				if (GetTokenInformation(hToken, TokenLinkedToken,
				                        &hUnfilteredToken, sizeof(HANDLE), &dwSize))
				{
					// Check if this original token contains admin SID
					if (CheckTokenMembership(hUnfilteredToken, &adminSid, pIsAdmin))
					{
						bResult = TRUE;
					}
					CloseHandle(hUnfilteredToken);
				}
			}
			else
			{
				*pIsAdmin = IsUserAnAdmin();
				bResult = TRUE;
			}
		}
		CloseHandle(hToken);
		return bResult;
	}
}

namespace global
{
	std::string Data::virtualDiskSerial(std::string_view serial, bool ataWordOrder) const
	{
		const std::string normalized = normalize_disk_serial(serial, ataWordOrder);
		if (normalized.empty()) return {};
		std::lock_guard lock(m_diskMutex);
		if (const auto found = m_virtualDiskSerials.find(normalized); found != m_virtualDiskSerials.end())
		{
			return found->second;
		}
		std::string result = std::format("{:016X}", hash_identity(m_envFlag ^ 0x4449534BULL, normalized));
		result.resize(std::min(result.size(), normalized.size()));
		m_virtualDiskSerials.emplace(normalized, result);
		m_virtualDiskSerials.emplace(result, result);
		return result;
	}

	std::string Data::virtualGuid(std::string_view guid) const
	{
		const std::string_view source = guid;
		const bool wrapped = guid.size() == 38 && guid.front() == '{' && guid.back() == '}';
		if (wrapped) guid = guid.substr(1, 36);
		if (guid.size() != 36) return std::string{source};
		std::string normalized{guid};
		for (std::size_t i = 0; i < normalized.size(); ++i)
		{
			char& c = normalized[i];
			if (i == 8 || i == 13 || i == 18 || i == 23)
			{
				if (c != '-') return std::string{source};
			}
			else if (c >= 'a' && c <= 'f') c = static_cast<char>(c - 'a' + 'A');
			else if (!((c >= 'A' && c <= 'F') || (c >= '0' && c <= '9')))
				return std::string{source};
		}
		std::lock_guard lock(m_guidMutex);
		std::string result;
		if (const auto found = m_virtualGuids.find(normalized); found != m_virtualGuids.end())
		{
			result = found->second;
		}
		else
		{
			std::string hex = std::format("{:016X}{:016X}",
				hash_identity(m_envFlag ^ 0x4755494441ULL, normalized),
				hash_identity(m_envFlag ^ 0x4755494442ULL, normalized));
			hex[12] = '4';
			hex[16] = '8';
			result = std::format("{}-{}-{}-{}-{}", hex.substr(0, 8), hex.substr(8, 4),
				hex.substr(12, 4), hex.substr(16, 4), hex.substr(20));
			m_virtualGuids.emplace(normalized, result);
			m_virtualGuids.emplace(result, result);
		}
		return wrapped ? std::format("{{{}}}", result) : result;
	}

	void Data::virtualMac(std::uint8_t* address, std::size_t length) const
	{
		if (!address || length != 6) return;
		std::uint64_t originalKey = 0;
		for (std::size_t i = 0; i < length; ++i)
		{
			originalKey |= std::uint64_t{address[i]} << (i * 8);
		}
		std::lock_guard lock(m_macMutex);
		if (const auto found = m_virtualMacs.find(originalKey); found != m_virtualMacs.end())
		{
			for (std::size_t i = 0; i < length; ++i)
			{
				address[i] = static_cast<std::uint8_t>(found->second >> (i * 8));
			}
			return;
		}
		const std::string_view source{reinterpret_cast<const char*>(address), length};
		const std::uint64_t hash = hash_identity(m_envFlag ^ 0x4D4143ULL, source);
		const std::array original{address[3], address[4], address[5]};
		for (std::size_t i = 0; i < 3; ++i)
		{
			address[i + 3] = static_cast<std::uint8_t>(hash >> (i * 8));
		}
		if (original[0] == address[3] && original[1] == address[4] && original[2] == address[5])
		{
			address[5] ^= 1;
		}
		std::uint64_t virtualKey = 0;
		for (std::size_t i = 0; i < length; ++i)
		{
			virtualKey |= std::uint64_t{address[i]} << (i * 8);
		}
		try
		{
			m_virtualMacs.emplace(originalKey, virtualKey);
			m_virtualMacs.emplace(virtualKey, virtualKey);
		}
		catch (...) {}
	}

	void Data::initialize(SystemVersionInfo versionInfo, std::uint64_t envFlag, unsigned long envIndex, std::wstring_view rootPath)
	{
		m_sysVersion = versionInfo;
		m_envFlag = envFlag;
		m_envIndex = envIndex;
		m_envFlagName = std::format(L"{:016X}", envFlag);
		m_envFlagNameA = std::format("{:016X}", envFlag);
		m_rootPath = rootPath;

		initializePrivilegesAbout();
		initializeRegistry();
		initializeDllFullPath();
		initializeKnownFolderPath();
		initializeMisc();

		// std::wcout.imbue(std::locale(""));
		// InitConsole();
	}

	static constexpr std::wstring_view PREFIX_TO_CHECK(LR"(\??\)");

	bool Data::isInKnownFolderPath(std::wstring_view path) const
	{
		if (m_knownFolders.empty())
		{
			return false;
		}

		if (!path.starts_with(PREFIX_TO_CHECK))
		{
			return false;
		}

		std::wstring_view pathToCheck = path.substr(PREFIX_TO_CHECK.length());
		std::wstring lowerPath(pathToCheck);
		std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), std::towlower);

		std::wstring envRoot = (std::filesystem::path{m_rootPath} / L"Env").lexically_normal().native();
		std::transform(envRoot.begin(), envRoot.end(), envRoot.begin(), std::towlower);
		if (!envRoot.ends_with(L'\\'))
		{
			envRoot += L'\\';
		}
		if (lowerPath.contains(L"microsoft")
			|| lowerPath.contains(L"nvidia")
			|| lowerPath.contains(L"amd")
			|| lowerPath.starts_with(envRoot))
		{
			return false;
		}
		//auto toLowerIterNow = lowerPath.begin();
		for (const std::wstring& knownFolder : m_knownFolders)
		{
			if (knownFolder.length() > lowerPath.length())
			{
				continue;
			}
			// if (const size_t alreadyToLowerCount = toLowerIterNow - lowerPath.begin();
			// 	alreadyToLowerCount < knownFolder.length())
			// {
			// 	const size_t needToLowerCount = knownFolder.length() - alreadyToLowerCount;
			// 	const auto last = toLowerIterNow + needToLowerCount;
			// 	std::transform(toLowerIterNow, last, toLowerIterNow, std::towlower);
			// 	toLowerIterNow = last;
			// }
			if (!lowerPath.starts_with(knownFolder))
			{
				continue;
			}
			return true;
		}
		return false;
	}

	std::optional<std::wstring> Data::getRedirectPath(std::wstring_view knownFolderPath) const
	{
		static constexpr std::wstring_view driverMarker(LR"(:\)");

		try
		{
			namespace fs = std::filesystem;
			if (const size_t driverPos = knownFolderPath.find(driverMarker); driverPos != std::wstring_view::npos)
			{
				const fs::path indexPath{std::format(L"{}", m_envIndex)};
				const fs::path relativePath{knownFolderPath.substr(driverPos + driverMarker.length())};
				const fs::path redirectPath{fs::weakly_canonical(fs::path{m_rootPath} / fs::path{L"Env"} / indexPath / relativePath)};
				return std::format(L"{}{}", PREFIX_TO_CHECK, redirectPath.native());
			}
		}
		catch (...)
		{
		}
		return std::nullopt;
	}

	void Data::initializePrivilegesAbout()
	{
		TOKEN_ELEVATION_TYPE elevationType = TokenElevationTypeDefault;
		BOOL bIsAdmin = FALSE;
		if (get_process_elevation(&elevationType, &bIsAdmin))
		{
			if (elevationType != TokenElevationTypeLimited)
			{
				m_bIsNonLimitedAdmin = bIsAdmin ? true : false;
			}
		}
	}

	void Data::initializeRegistry()
	{
		m_appKey = RegKey{
			[&]()-> HKEY
			{
				namespace fs = std::filesystem;
				const fs::path envFile{fs::weakly_canonical(fs::path{m_rootPath} / fs::path{L"Env"} / fs::path{std::format(L"{}", m_envIndex)} / fs::path{m_envFlagName})};
				HKEY hKey;
				if (RegLoadAppKeyW(envFile.native().c_str(), &hKey, KEY_ALL_ACCESS, 0, 0) != ERROR_SUCCESS)
				{
					throw std::runtime_error("Failed to load app key");
				}
				return hKey;
			}
		};
	}

	void Data::initializeDllFullPath()
	{
		namespace fs = std::filesystem;
		if constexpr (CURRENT_ARCH_BIT == ArchBit::Bit64)
		{
			m_dllFullPath = fs::path{fs::weakly_canonical(fs::path{m_rootPath} / fs::path{L"bin"} / fs::path{std::format(L"{}_64.bin", m_envFlagName)})}.string();
		}
		else
		{
			m_dllFullPath = fs::path{fs::weakly_canonical(fs::path{m_rootPath} / fs::path{L"bin"} / fs::path{std::format(L"{}_32.bin", m_envFlagName)})}.string();
		}
	}

	void Data::initializeKnownFolderPath()
	{
		static const std::array rfidArray = {FOLDERID_LocalAppData, FOLDERID_LocalAppDataLow, FOLDERID_RoamingAppData, FOLDERID_SavedGames, FOLDERID_ProgramData};

		for (size_t i = 0; i < rfidArray.size(); ++i)
		{
			const KNOWNFOLDERID& rfid = rfidArray[i];
			wchar_t* out;
			if (S_OK == SHGetKnownFolderPath(rfid, 0, nullptr, &out))
			{
				std::wstring_view sv{out};
				std::transform(sv.begin(), sv.end(), out, std::towlower);
				if (std::optional<std::wstring> redirectPath = getRedirectPath(sv))
				{
					if (ensure_dir_exists(redirectPath.value(), true))
					{
						m_knownFolders.push_back(std::format(L"{}\\", sv));
					}
				}
				CoTaskMemFree(out);
			}
		}
	}

	void Data::initializeMisc()
	{
		m_inputSyncMsgId = RegisterWindowMessageW(L"{63B40BDA-A2D1-4516-BDBB-E1E2A960D31E}_INPUT_SYNC");
		if (!m_inputSyncMsgId)
		{
			m_inputSyncMsgId = 9527;
		}
	}

	bool ensure_dir_exists(std::wstring_view fullName, bool bIsDir)
	{
		try
		{
			namespace fs = std::filesystem;
			const fs::path path{fullName};
			if (bIsDir)
			{
				fs::create_directories(path);
			}
			else
			{
				fs::create_directories(path.parent_path());
			}
			return true;
		}
		catch (...)
		{
		}
		return false;
	}
}
