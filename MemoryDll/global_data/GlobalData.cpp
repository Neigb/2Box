// ReSharper disable CppUseRangeAlgorithm
module;
#include "DeviceIdentityProvider.hpp"
#include "DeviceLaunch.hpp"
#include "InstanceIdentity.hpp"
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
	std::wstring widen_ascii(const std::string& text)
	{
		return std::wstring{text.begin(), text.end()};
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
		if (!storageSimulated()) return std::string{serial};
		return m_device->virtualSerial(devid::SerialDomain::Disk, serial, ataWordOrder);
	}

	std::string Data::virtualSystemSerial(std::string_view serial) const
	{
		if (!smbiosSimulated()) return std::string{serial};
		return m_device->virtualSerial(devid::SerialDomain::SmbiosSystem, serial);
	}

	std::string Data::virtualBoardSerial(std::string_view serial) const
	{
		if (!smbiosSimulated()) return std::string{serial};
		return m_device->virtualSerial(devid::SerialDomain::SmbiosBoard, serial);
	}

	std::string Data::virtualChassisSerial(std::string_view serial) const
	{
		if (!smbiosSimulated()) return std::string{serial};
		return m_device->virtualSerial(devid::SerialDomain::SmbiosChassis, serial);
	}

	std::string Data::virtualPnpInstance(bool network, std::string_view suffix) const
	{
		if (network ? !networkSimulated() : !storageSimulated()) return std::string{suffix};
		return m_device->virtualSerial(network ? devid::SerialDomain::PnpNetworkInstance : devid::SerialDomain::PnpStorageInstance, suffix);
	}

	std::string Data::virtualAdapterGuid(std::string_view guid) const
	{
		if (!networkSimulated()) return std::string{guid};
		return m_device->virtualAdapterGuid(guid);
	}

	std::string Data::virtualSystemUuid(std::string_view uuid) const
	{
		if (!smbiosSimulated()) return std::string{uuid};
		return m_device->virtualSystemUuid(uuid);
	}

	std::string Data::virtualMachineGuid(std::string_view guid) const
	{
		if (!osSimulated()) return std::string{guid};
		return m_device->virtualMachineGuid(guid);
	}

	void Data::virtualMac(std::uint8_t* address, std::size_t length) const
	{
		if (!networkSimulated()) return;
		m_device->virtualMac(address, length);
	}

	void Data::rewriteSmbiosTable(std::uint8_t* table, std::size_t size) const
	{
		if (!smbiosSimulated()) return;
		m_device->rewriteSmbiosTable(table, size);
	}

	void Data::initialize(SystemVersionInfo versionInfo, const devid::InstanceIdentity& instance, std::wstring_view rootPath,
	                      devid::LaunchConfig launchConfig, std::string launchConfigText)
	{
		m_sysVersion = versionInfo;
		m_instance = instance;
		m_objectNamespaceNameA = instance.objectNamespaceSuffix();
		m_objectNamespaceName = widen_ascii(m_objectNamespaceNameA);
		m_registrySuffixName = widen_ascii(instance.registrySuffix());
		m_rootPath = rootPath;
		m_hookPlan = devid::make_hook_plan(launchConfig);
		m_launchConfigText = std::move(launchConfigText);
		if (launchConfig.profile && launchConfig.deviceSimulationEnabled())
		{
			m_device = std::make_unique<devid::DeviceIdentityProvider>(*launchConfig.profile);
		}

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
				const fs::path indexPath{std::format(L"{}", m_instance.instanceIndex)};
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
				const fs::path envFile{fs::weakly_canonical(fs::path{m_rootPath} / fs::path{L"Env"} / fs::path{std::format(L"{}", m_instance.instanceIndex)} / fs::path{widen_ascii(m_instance.hiveName())})};
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
			m_dllFullPath = fs::path{fs::weakly_canonical(fs::path{m_rootPath} / fs::path{L"bin"} / fs::path{std::format(L"{}_64.bin", widen_ascii(m_instance.dllStem()))})}.string();
		}
		else
		{
			m_dllFullPath = fs::path{fs::weakly_canonical(fs::path{m_rootPath} / fs::path{L"bin"} / fs::path{std::format(L"{}_32.bin", widen_ascii(m_instance.dllStem()))})}.string();
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
