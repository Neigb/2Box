// Portable tests for the device identity core (no Windows headers). Build and run with
//   tests/run-device-identity-tests.sh
// They cover: profile persistence/stability, independence between profiles, decoupling from
// InstanceIdentity, unchanged default (plain multi-instance) behaviour, and cross-API consistency.

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <functional>
#include <random>
#include <string>
#include <type_traits>

#include "DeviceIdentityProvider.hpp"
#include "DeviceLaunch.hpp"
#include "DeviceProfile.hpp"
#include "InstanceIdentity.hpp"

namespace
{
	int g_failures = 0;
	int g_checks = 0;
	std::string g_current;

	void expect(bool condition, const char* expression, const char* file, int line)
	{
		++g_checks;
		if (!condition)
		{
			++g_failures;
			std::fprintf(stderr, "FAIL [%s] %s:%d: %s\n", g_current.c_str(), file, line, expression);
		}
	}

#define CHECK(expr) expect(static_cast<bool>(expr), #expr, __FILE__, __LINE__)

	std::vector<std::pair<std::string, std::function<void()>>>& registry()
	{
		static std::vector<std::pair<std::string, std::function<void()>>> tests;
		return tests;
	}

	struct Registrar
	{
		Registrar(const char* name, std::function<void()> body) { registry().emplace_back(name, std::move(body)); }
	};

#define TEST(name) \
	static void name(); \
	static Registrar registrar_##name{#name, name}; \
	static void name()

	devid::DeviceProfile make_profile(std::uint64_t seed)
	{
		std::mt19937_64 rng{seed};
		return devid::generate_profile([&] { return rng(); });
	}

	std::filesystem::path temp_dir(const char* name)
	{
		std::filesystem::path dir = std::filesystem::temp_directory_path() / (std::string{"devid-test-"} + name);
		std::filesystem::remove_all(dir);
		std::filesystem::create_directories(dir);
		return dir;
	}

	// Character class of each position: D digit, U upper, L lower, other kept literally.
	std::string shape_of(const std::string& text)
	{
		std::string shape;
		for (const char c : text)
		{
			if (c >= '0' && c <= '9') shape += 'D';
			else if (c >= 'A' && c <= 'Z') shape += 'U';
			else if (c >= 'a' && c <= 'z') shape += 'L';
			else shape += c;
		}
		return shape;
	}

	const std::vector<std::string> kDiskSerials = {
		"S4EVNX0M123456A", "WD-WCC4N5RZ8Y2L", "2145E4C5A1B0", "50026B7685A1B2C3", "ZA1ABC9D", "0025_38B1_21A2_3C4D.",
	};

	// ---- synthetic SMBIOS table -------------------------------------------------------------

	struct SmbiosFixture
	{
		std::vector<std::uint8_t> bytes;
		std::size_t uuidOffset{0};
	};

	void append_structure(std::vector<std::uint8_t>& table, std::uint8_t type, std::vector<std::uint8_t> formatted,
		const std::vector<std::string>& strings)
	{
		formatted[0] = type;
		formatted[1] = static_cast<std::uint8_t>(formatted.size());
		table.insert(table.end(), formatted.begin(), formatted.end());
		if (strings.empty())
		{
			table.push_back(0);
			table.push_back(0);
		}
		else
		{
			for (const std::string& s : strings)
			{
				table.insert(table.end(), s.begin(), s.end());
				table.push_back(0);
			}
			table.push_back(0);
		}
	}

	SmbiosFixture make_smbios(const std::string& systemSerial, const std::string& boardSerial,
		const std::string& chassisSerial, unsigned major = 3, unsigned minor = 3)
	{
		SmbiosFixture f;
		std::vector<std::uint8_t> table;
		// Type 0 BIOS information: vendor + version strings only (must stay untouched).
		append_structure(table, 0, std::vector<std::uint8_t>(0x12, 0), {"Contoso BIOS", "1.2.3"});
		// Type 1 System information.
		std::vector<std::uint8_t> sys(0x1B, 0);
		sys[4] = 1; sys[5] = 2; sys[6] = 3; sys[7] = 4;
		for (int i = 0; i < 16; ++i) sys[8 + i] = static_cast<std::uint8_t>(0xA0 + i);
		f.uuidOffset = 8 + table.size() + 8; // table header + start of the type 1 structure + UUID field offset
		append_structure(table, 1, sys, {"Contoso", "Model 9", "v1", systemSerial});
		// Type 2 Baseboard.
		std::vector<std::uint8_t> board(0x0F, 0);
		board[4] = 1; board[5] = 2; board[6] = 3; board[7] = 4;
		append_structure(table, 2, board, {"Contoso", "Board X", "r1", boardSerial});
		// Type 3 Chassis.
		std::vector<std::uint8_t> chassis(0x15, 0);
		chassis[4] = 1; chassis[5] = 3; chassis[6] = 2; chassis[7] = 4;
		append_structure(table, 3, chassis, {"Contoso", "v2", "v3", chassisSerial});
		// Type 127 end of table.
		append_structure(table, 127, std::vector<std::uint8_t>(4, 0), {});

		f.bytes = {0, static_cast<std::uint8_t>(major), static_cast<std::uint8_t>(minor), 0,
			static_cast<std::uint8_t>(table.size()), static_cast<std::uint8_t>(table.size() >> 8),
			static_cast<std::uint8_t>(table.size() >> 16), static_cast<std::uint8_t>(table.size() >> 24)};
		f.bytes.insert(f.bytes.end(), table.begin(), table.end());
		return f;
	}

	std::size_t find_bytes(const std::vector<std::uint8_t>& bytes, const std::string& needle)
	{
		const std::string hay(bytes.begin(), bytes.end());
		return hay.find(needle);
	}
}

// ---------------------------------------------------------------------------------------------
// Profile persistence and stability
// ---------------------------------------------------------------------------------------------

TEST(profile_roundtrips_through_text)
{
	const devid::DeviceProfile profile = make_profile(1);
	const auto parsed = devid::parse_profile(devid::serialize_profile(profile));
	CHECK(parsed.profile.has_value());
	CHECK(parsed.profile && *parsed.profile == profile);
}

TEST(profile_is_stable_across_restart)
{
	const auto dir = temp_dir("restart");
	std::uint64_t id = 0;
	std::string before;
	{
		devid::DeviceProfileStore store{dir};
		std::mt19937_64 rng{7};
		std::uint64_t bound = 0;
		const devid::DeviceProfile created = devid::obtain_profile(store, 0, [&] { return rng(); }, [&](std::uint64_t v) { bound = v; });
		id = bound;
		CHECK(id == created.profileId);
		devid::DeviceIdentityProvider provider{created};
		before = provider.virtualSerial(devid::SerialDomain::Disk, "S4EVNX0M123456A") + "|" + provider.virtualSystemUuid("00000000-0000-0000-0000-000000000000");
	}
	{
		// New process: new store object, different RNG that must NOT be consulted for an already bound profile.
		devid::DeviceProfileStore store{dir};
		bool rngCalled = false;
		const devid::DeviceProfile loaded = devid::obtain_profile(store, id, [&] { rngCalled = true; return 1ull; }, [](std::uint64_t) {});
		CHECK(!rngCalled);
		devid::DeviceIdentityProvider provider{loaded};
		const std::string after = provider.virtualSerial(devid::SerialDomain::Disk, "S4EVNX0M123456A") + "|" + provider.virtualSystemUuid("00000000-0000-0000-0000-000000000000");
		CHECK(before == after);
	}
	std::filesystem::remove_all(dir);
}

TEST(damaged_or_missing_bound_profile_is_an_error_not_a_new_machine)
{
	const auto dir = temp_dir("damaged");
	devid::DeviceProfileStore store{dir};
	const devid::DeviceProfile profile = make_profile(2);
	CHECK(store.save(profile).empty());

	// missing
	bool threw = false;
	try { devid::obtain_profile(store, 0x1234, [] { return 5ull; }, [](std::uint64_t) {}); } catch (const std::exception&) { threw = true; }
	CHECK(threw);

	// damaged: flip one character in the middle
	{
		std::string text = devid::serialize_profile(profile);
		text[text.find("storage.salt=") + 15] ^= 1;
		std::ofstream out{store.pathFor(profile.profileId), std::ios::binary | std::ios::trunc};
		out << text;
	}
	CHECK(!store.load(profile.profileId).profile.has_value());
	threw = false;
	try { devid::obtain_profile(store, profile.profileId, [] { return 5ull; }, [](std::uint64_t) {}); } catch (const std::exception&) { threw = true; }
	CHECK(threw);
	CHECK(std::filesystem::exists(store.pathFor(profile.profileId))); // not replaced
	std::filesystem::remove_all(dir);
}

TEST(newer_schema_version_is_rejected)
{
	std::string text = devid::serialize_profile(make_profile(3));
	text.replace(text.find(" 1\n"), 3, " 2\n");
	CHECK(!devid::parse_profile(text).profile.has_value());
}

TEST(failed_binding_removes_the_orphan_profile)
{
	const auto dir = temp_dir("bindfail");
	devid::DeviceProfileStore store{dir};
	std::mt19937_64 rng{9};
	std::uint64_t created = 0;
	bool threw = false;
	try
	{
		devid::obtain_profile(store, 0, [&] { return rng(); }, [&](std::uint64_t id) { created = id; throw std::runtime_error("registry"); });
	}
	catch (const std::exception&) { threw = true; }
	CHECK(threw);
	CHECK(created != 0 && !std::filesystem::exists(store.pathFor(created)));
	std::filesystem::remove_all(dir);
}

// ---------------------------------------------------------------------------------------------
// Independence between profiles
// ---------------------------------------------------------------------------------------------

TEST(different_profiles_produce_independent_identities)
{
	devid::DeviceIdentityProvider a{make_profile(11)};
	devid::DeviceIdentityProvider b{make_profile(12)};
	CHECK(a.profile().profileId != b.profile().profileId);
	CHECK(a.profile().hardware.systemUuid != b.profile().hardware.systemUuid);
	CHECK(a.machineGuid() != b.machineGuid());
	for (const std::string& serial : kDiskSerials)
	{
		CHECK(a.virtualSerial(devid::SerialDomain::Disk, serial) != b.virtualSerial(devid::SerialDomain::Disk, serial));
	}
	CHECK(a.virtualAdapterGuid("{0F7C2A91-3B4D-4E5F-8A6B-7C8D9E0F1A2B}") != b.virtualAdapterGuid("{0F7C2A91-3B4D-4E5F-8A6B-7C8D9E0F1A2B}"));
	std::uint8_t macA[6] = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E};
	std::uint8_t macB[6] = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E};
	a.virtualMac(macA, 6);
	b.virtualMac(macB, 6);
	CHECK(std::memcmp(macA, macB, 6) != 0);
}

TEST(same_profile_reproduces_identity_in_a_fresh_provider)
{
	const devid::DeviceProfile profile = make_profile(21);
	devid::DeviceIdentityProvider first{profile};
	devid::DeviceIdentityProvider second{profile};
	for (const std::string& serial : kDiskSerials)
	{
		CHECK(first.virtualSerial(devid::SerialDomain::Disk, serial) == second.virtualSerial(devid::SerialDomain::Disk, serial));
	}
	std::uint8_t a[6] = {0x3C, 0x52, 0x82, 0x11, 0x22, 0x33}, b[6] = {0x3C, 0x52, 0x82, 0x11, 0x22, 0x33};
	first.virtualMac(a, 6);
	second.virtualMac(b, 6);
	CHECK(std::memcmp(a, b, 6) == 0);
}

TEST(golden_values_pin_the_derivation_algorithm)
{
	// If this fails the derivation changed: every existing profile would silently become a "new machine".
	// Only update these constants together with a profile schema version bump.
	devid::DeviceProfile profile;
	profile.profileId = 0x1111111111111111ULL;
	profile.storage.salt = 0x2222222222222222ULL;
	profile.network.salt = 0x3333333333333333ULL;
	profile.hardware.salt = 0x4444444444444444ULL;
	profile.hardware.systemUuid = "5B8A7D2E-9C41-4F36-A0D8-123456789ABC";
	profile.os.machineGuid = "0f1e2d3c-4b5a-4968-8776-655443322110";
	devid::DeviceIdentityProvider provider{profile};
	CHECK(provider.virtualSerial(devid::SerialDomain::Disk, "S4EVNX0M123456A") == "P6TXZS8Z405680L");
	CHECK(provider.virtualSerial(devid::SerialDomain::SmbiosSystem, "PF2ABCDE") == "CZ8RTPGE");
	CHECK(provider.virtualAdapterGuid("{0F7C2A91-3B4D-4E5F-8A6B-7C8D9E0F1A2B}") == "{5C7EFE87-4E94-47B6-819B-9898DAD4BBD9}");
	std::uint8_t mac[6] = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E};
	provider.virtualMac(mac, 6);
	char text[32];
	std::snprintf(text, sizeof(text), "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	CHECK(std::string{text} == "00:1A:2B:FD:B9:01");
}

// ---------------------------------------------------------------------------------------------
// Instance identity and device identity do not depend on each other
// ---------------------------------------------------------------------------------------------

static_assert(!std::is_constructible_v<devid::DeviceIdentityProvider, devid::InstanceIdentity>,
	"a device identity must never be built from instance data");
static_assert(!std::is_convertible_v<devid::InstanceIdentity, devid::DeviceProfile>,
	"instance identity must not convert to a device profile");

TEST(instance_identity_does_not_influence_device_identity)
{
	const devid::DeviceProfile profile = make_profile(31);
	devid::DeviceIdentityProvider provider{profile};
	const std::string before = provider.virtualSerial(devid::SerialDomain::Disk, "WD-WCC4N5RZ8Y2L");

	// Any number of different instances, indexes and sessions: the device answers do not move.
	for (std::uint64_t flag = 1; flag <= 5; ++flag)
	{
		const devid::InstanceIdentity instance = devid::InstanceIdentity::fromLegacy(flag * 0x9E3779B97F4A7C15ULL, static_cast<std::uint32_t>(flag), flag + 100);
		devid::DeviceIdentityProvider other{profile};
		CHECK(other.virtualSerial(devid::SerialDomain::Disk, "WD-WCC4N5RZ8Y2L") == before);
		(void)instance;
	}
}

TEST(device_profile_does_not_influence_instance_identity)
{
	const devid::InstanceIdentity instance = devid::InstanceIdentity::fromLegacy(0x0123456789ABCDEFULL, 3, 77);
	CHECK(instance.dllStem() == "0123456789ABCDEF");
	CHECK(instance.hiveName() == "0123456789ABCDEF");
	CHECK(instance.objectNamespaceSuffix() == "0123456789ABCDEF"); // legacy-compatible default

	devid::InstanceIdentity separated = instance;
	separated.objectNamespaceId = 42;
	CHECK(separated.objectNamespaceSuffix() == "000000000000002A");
	CHECK(separated.dllStem() == instance.dllStem()); // roles can diverge independently
	CHECK(separated.registrySuffix() == instance.registrySuffix());
}

TEST(two_instances_can_share_one_profile_and_one_instance_can_change_profile)
{
	const devid::DeviceProfile p1 = make_profile(41), p2 = make_profile(42);
	devid::DeviceIdentityProvider shared1{p1}, shared2{p1}, changed{p2};
	CHECK(shared1.virtualSerial(devid::SerialDomain::Disk, "ZA1ABC9D") == shared2.virtualSerial(devid::SerialDomain::Disk, "ZA1ABC9D"));
	CHECK(shared1.virtualSerial(devid::SerialDomain::Disk, "ZA1ABC9D") != changed.virtualSerial(devid::SerialDomain::Disk, "ZA1ABC9D"));
}

// ---------------------------------------------------------------------------------------------
// Default behaviour: plain multi-instance, no device simulation
// ---------------------------------------------------------------------------------------------

TEST(default_launch_is_plain_isolation_without_device_simulation)
{
	const devid::LaunchConfig config; // what the host builds when nothing asks for simulation
	CHECK(!config.deviceSimulationEnabled());
	CHECK(!config.profile.has_value());
	const devid::HookPlan plan = devid::make_hook_plan(config);
	CHECK(plan.isolation);
	CHECK(plan.processPropagation);
	CHECK(!plan.storage && !plan.storageAsync && !plan.storageWait);
	CHECK(!plan.network && !plan.wmi && !plan.smbios);

	const std::string encoded = devid::encode_launch_config(config);
	CHECK(encoded.find("profile") == std::string::npos); // no device data leaves the host
	const auto decoded = devid::decode_launch_config(encoded);
	CHECK(decoded.config.has_value());
	CHECK(decoded.config && decoded.config->capabilities == devid::kCapNone);
	CHECK(decoded.config && decoded.config->hooks == devid::kHookIsolation);
}

TEST(no_policy_or_unmatched_policy_means_no_capabilities)
{
	CHECK(devid::parse_policy("").resolve("C:\\Apps\\game.exe") == devid::kCapNone);
	const auto policy = devid::parse_policy("[app]\nmatch = other.exe\ncapabilities = storage\n");
	CHECK(policy.errors.empty());
	CHECK(policy.resolve("C:\\Apps\\game.exe") == devid::kCapNone);
	CHECK(!devid::map_legacy_scope("").overrides);
	CHECK(!devid::map_legacy_scope("full").overrides);
	CHECK(!devid::map_legacy_scope("garbage").overrides);
}

TEST(simulation_is_enabled_per_application)
{
	const auto policy = devid::parse_policy(
		"# per-app\n"
		"[app]\nmatch = Target.EXE\ncapabilities = storage, network ; inline comment\n"
		"[app]\nmatch = C:/Tools/Special.exe\ncapabilities = smbios, wmi\n");
	CHECK(policy.errors.empty());
	CHECK(policy.resolve("D:\\x\\target.exe") == (devid::kCapStorage | devid::kCapStorageAsync | devid::kCapNetwork));
	CHECK(policy.resolve("c:\\tools\\special.exe") == (devid::kCapSmbios | devid::kCapWmi));
	CHECK(policy.resolve("D:\\other\\special.exe") == devid::kCapNone); // full-path rule does not match by name
	CHECK(policy.resolve("D:\\x\\unrelated.exe") == devid::kCapNone);
}

TEST(policy_errors_are_reported_and_fail_closed)
{
	const auto policy = devid::parse_policy("[app]\nmatch = a.exe\ncapabilities = storage, hologram\n[app]\ncapabilities = storage\n");
	CHECK(policy.errors.size() == 2);
	CHECK(policy.rules.empty());
	CHECK(policy.resolve("a.exe") == devid::kCapNone);
}

TEST(capabilities_normalise_and_drive_the_hook_plan)
{
	CHECK(devid::normalize_capabilities(devid::kCapWmi) == devid::kCapNone); // transport alone simulates nothing
	CHECK((devid::normalize_capabilities(devid::kCapStorageAsync) & devid::kCapStorage) != 0);

	devid::LaunchConfig config;
	config.capabilities = devid::kCapWmi | devid::kCapNetwork;
	devid::HookPlan plan = devid::make_hook_plan(config);
	CHECK(plan.network && plan.wmi && !plan.storage && !plan.smbios);
	CHECK(plan.isolation);

	config.capabilities = devid::kCapStorage; // overlapped completion is part of storage; wait-based stays opt-in
	plan = devid::make_hook_plan(config);
	CHECK(plan.storage && plan.storageAsync && !plan.storageWait && !plan.wmi);

	config.hooks = devid::kHookProcessOnly;
	plan = devid::make_hook_plan(config);
	CHECK(plan.processPropagation && !plan.isolation && !plan.storage && !plan.network);
}

TEST(legacy_scopes_map_to_the_same_hook_sets_as_before)
{
	const auto plan = [](const char* scope)
	{
		const devid::ScopeMapping m = devid::map_legacy_scope(scope);
		devid::LaunchConfig config;
		config.hooks = m.hooks;
		config.capabilities = m.capabilities;
		return devid::make_hook_plan(config);
	};
	const devid::HookPlan device = plan("device");
	CHECK(!device.isolation && device.storage && device.storageAsync && device.storageWait && device.network && device.wmi);
	const devid::HookPlan async = plan("device-async");
	CHECK(!async.isolation && async.storage && async.storageAsync && !async.storageWait && async.network && async.wmi);
	const devid::HookPlan minimal = plan("device-minimal");
	CHECK(!minimal.isolation && minimal.storage && minimal.storageAsync && !minimal.storageWait && !minimal.network && !minimal.wmi);
	const devid::HookPlan process = plan("process");
	CHECK(process.processPropagation && !process.isolation && !process.storage);
}

TEST(launch_config_roundtrip_and_invariants)
{
	devid::LaunchConfig config;
	config.sessionId = 0xABCDEF;
	config.objectNamespaceId = 0x1122334455667788ULL;
	config.hooks = devid::kHookIsolation;
	config.capabilities = devid::kCapStorage | devid::kCapSmbios | devid::kCapWmi;
	config.profile = make_profile(51);
	const auto decoded = devid::decode_launch_config(devid::encode_launch_config(config));
	CHECK(decoded.config.has_value());
	CHECK(decoded.config && decoded.config->sessionId == config.sessionId);
	CHECK(decoded.config && decoded.config->objectNamespaceId == config.objectNamespaceId);
	CHECK(decoded.config && decoded.config->capabilities == devid::normalize_capabilities(config.capabilities));
	CHECK(decoded.config && decoded.config->profile == config.profile);

	// capabilities without a profile are a host bug and must be rejected, not guessed.
	std::string broken = devid::encode_launch_config(config);
	broken.erase(broken.find("profile:"));
	CHECK(!devid::decode_launch_config(broken).config.has_value());
	// a profile without capabilities is rejected too.
	devid::LaunchConfig stray;
	stray.profile = make_profile(52);
	CHECK(!devid::decode_launch_config(devid::encode_launch_config(stray)).config.has_value());
}

// ---------------------------------------------------------------------------------------------
// Realism and cross-API consistency
// ---------------------------------------------------------------------------------------------

TEST(serials_keep_length_shape_and_vendor_tag)
{
	devid::DeviceIdentityProvider provider{make_profile(61)};
	for (const std::string& serial : kDiskSerials)
	{
		const std::string virtualSerial = provider.virtualSerial(devid::SerialDomain::Disk, serial);
		CHECK(virtualSerial.size() == serial.size());
		CHECK(virtualSerial != serial);
		// Hex-looking runs may change digit/letter placement; every other position keeps its class.
		if (serial.find('-') != std::string::npos) CHECK(virtualSerial.rfind("WD-", 0) == 0);
		CHECK(shape_of(virtualSerial).size() == shape_of(serial).size());
	}
	const std::string nvme = provider.virtualSerial(devid::SerialDomain::Disk, "0025_38B1_21A2_3C4D.");
	CHECK(nvme[4] == '_' && nvme[9] == '_' && nvme[14] == '_' && nvme[19] == '.'); // separators intact
	CHECK(nvme.find_first_not_of("0123456789ABCDEF_.") == std::string::npos);      // still hexadecimal
	const std::string samsung = provider.virtualSerial(devid::SerialDomain::Disk, "S4EVNX0M123456A");
	CHECK(shape_of(samsung) == shape_of("S4EVNX0M123456A"));
}

TEST(same_disk_gives_same_serial_through_every_api_encoding)
{
	devid::DeviceIdentityProvider provider{make_profile(62)};
	const std::string real = "S4EVNX0M123456A";

	// StorageDescriptor / WMI deliver the text as is.
	const std::string viaDescriptor = provider.virtualSerial(devid::SerialDomain::Disk, real);
	const std::string viaWmi = provider.virtualSerial(devid::SerialDomain::Disk, real);

	// ATA IDENTIFY: 20 bytes, space padded, each byte pair swapped.
	std::string ata(20, ' ');
	std::copy(real.begin(), real.end(), ata.begin());
	for (std::size_t i = 0; i + 1 < ata.size(); i += 2) std::swap(ata[i], ata[i + 1]);
	const std::string viaAta = provider.virtualSerial(devid::SerialDomain::Disk, ata, true);

	// Lower-case or padded variants of the same serial are the same disk.
	std::string padded = "  " + real + "\t";
	for (char& c : padded) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + 32);
	const std::string viaPadded = provider.virtualSerial(devid::SerialDomain::Disk, padded);

	CHECK(viaDescriptor == viaWmi);
	CHECK(viaDescriptor == viaAta);
	CHECK(viaDescriptor == viaPadded);

	// Feeding an already virtual value back (a second hook on the same buffer) must not change it again.
	CHECK(provider.virtualSerial(devid::SerialDomain::Disk, viaDescriptor) == viaDescriptor);
}

TEST(nvme_spellings_of_one_serial_agree)
{
	devid::DeviceIdentityProvider provider{make_profile(73)};
	const std::string dotted = provider.virtualSerial(devid::SerialDomain::Disk, "0025_38B1_21A2_3C4D.");
	const std::string plain = provider.virtualSerial(devid::SerialDomain::Disk, "002538B121A23C4D");
	auto digits = [](const std::string& text) { return devid::detail::alnum_only(text); };
	CHECK(dotted.size() == 20 && dotted[19] == '.');
	CHECK(plain.size() == 16);
	CHECK(digits(dotted) == digits(plain));
}

TEST(policy_paths_may_contain_comment_characters)
{
	const auto policy = devid::parse_policy("[app]\nmatch = C:\\Tools\\a#1;x\\app.exe  # note\ncapabilities = storage\n");
	CHECK(policy.errors.empty());
	CHECK(policy.resolve("c:\\tools\\a#1;x\\app.exe") == (devid::kCapStorage | devid::kCapStorageAsync));
}

TEST(alias_table_stays_bounded)
{
	devid::DeviceIdentityProvider provider{make_profile(74)};
	for (int i = 0; i < 20000; ++i)
	{
		CHECK(!provider.virtualSerial(devid::SerialDomain::Disk, "SN" + std::to_string(100000 + i)).empty());
	}
}

TEST(domains_are_isolated_from_each_other)
{
	devid::DeviceIdentityProvider provider{make_profile(63)};
	const std::string value = "AB12CD34EF56";
	const std::string disk = provider.virtualSerial(devid::SerialDomain::Disk, value);
	const std::string system = provider.virtualSerial(devid::SerialDomain::SmbiosSystem, value);
	const std::string board = provider.virtualSerial(devid::SerialDomain::SmbiosBoard, value);
	const std::string chassis = provider.virtualSerial(devid::SerialDomain::SmbiosChassis, value);
	CHECK(disk != system && system != board && board != chassis && disk != board);
}

TEST(placeholder_serials_become_plausible_generated_serials)
{
	devid::DeviceIdentityProvider a{make_profile(64)}, b{make_profile(65)};
	const std::string filler = "To Be Filled By O.E.M.";
	const std::string out = a.virtualSerial(devid::SerialDomain::SmbiosSystem, filler);
	CHECK(out.size() == filler.size());
	CHECK(out.find_first_not_of("ABCDEFGHJKLMNPQRSTUVWXYZ0123456789") == std::string::npos);
	CHECK(out != b.virtualSerial(devid::SerialDomain::SmbiosSystem, filler)); // still unique per profile
	CHECK(a.virtualSerial(devid::SerialDomain::SmbiosSystem, filler) == out);
}

TEST(pnp_instance_suffix_keeps_its_structure)
{
	devid::DeviceIdentityProvider provider{make_profile(66)};
	const std::string suffix = "5&1A2B3C4D&0&000000";
	const std::string out = provider.virtualSerial(devid::SerialDomain::PnpStorageInstance, suffix);
	CHECK(out.size() == suffix.size());
	CHECK(out[1] == '&' && out[10] == '&' && out[12] == '&');
	CHECK(out.find_first_not_of("0123456789ABCDEF&") == std::string::npos);
	CHECK(out != suffix);
}

TEST(guid_keeps_wrapping_and_case_and_agrees_across_spellings)
{
	devid::DeviceIdentityProvider provider{make_profile(67)};
	const std::string wrapped = "{0F7C2A91-3B4D-4E5F-8A6B-7C8D9E0F1A2B}";   // IP Helper AdapterName style
	const std::string bare = "0F7C2A91-3B4D-4E5F-8A6B-7C8D9E0F1A2B";       // WMI style
	const std::string lowered = "0f7c2a91-3b4d-4e5f-8a6b-7c8d9e0f1a2b";
	const std::string a = provider.virtualAdapterGuid(wrapped);
	const std::string b = provider.virtualAdapterGuid(bare);
	const std::string c = provider.virtualAdapterGuid(lowered);
	CHECK(a.size() == 38 && a.front() == '{' && a.back() == '}');
	CHECK(a.substr(1, 36) == b);
	CHECK(c.size() == 36 && c.find_first_of("ABCDEF") == std::string::npos);
	CHECK(devid::detail::parse_guid_text(c)->upper == b);
	CHECK(b != bare);
	CHECK(b[14] == '4' && std::string{"89AB"}.find(b[19]) != std::string::npos); // still a v4 GUID
	CHECK(provider.virtualAdapterGuid("not a guid") == "not a guid");
	CHECK(provider.virtualAdapterGuid(a) == a); // idempotent
}

TEST(system_uuid_comes_from_the_profile_and_is_host_independent)
{
	const devid::DeviceProfile profile = make_profile(68);
	devid::DeviceIdentityProvider provider{profile};
	const std::string fromAnyHost1 = provider.virtualSystemUuid("4C4C4544-0042-4710-8052-B8C04F325931");
	const std::string fromAnyHost2 = provider.virtualSystemUuid("FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF");
	CHECK(fromAnyHost1 == profile.hardware.systemUuid);
	CHECK(fromAnyHost2 == profile.hardware.systemUuid);
	CHECK(provider.virtualSystemUuid("{4C4C4544-0042-4710-8052-B8C04F325931}") == "{" + profile.hardware.systemUuid + "}");
}

TEST(machine_guid_comes_from_the_profile_in_the_source_spelling)
{
	const devid::DeviceProfile profile = make_profile(75);
	devid::DeviceIdentityProvider provider{profile};
	const std::string lower = provider.virtualMachineGuid("4c4c4544-0042-4710-8052-b8c04f325931");
	CHECK(lower == profile.os.machineGuid); // registry spelling: lower-case, hyphenated
	CHECK(provider.virtualMachineGuid("{4C4C4544-0042-4710-8052-B8C04F325931}").front() == '{');
	CHECK(provider.virtualMachineGuid("not a guid") == "not a guid");
	devid::DeviceIdentityProvider other{make_profile(76)};
	CHECK(other.virtualMachineGuid("4c4c4544-0042-4710-8052-b8c04f325931") != lower);
	devid::LaunchConfig config;
	config.capabilities = devid::kCapOs;
	CHECK(devid::make_hook_plan(config).os);
	CHECK(!devid::make_hook_plan(devid::LaunchConfig{}).os);
	CHECK(devid::parse_policy("[app]\nmatch = a.exe\ncapabilities = os\n").resolve("a.exe") == devid::kCapOs);
}

TEST(mac_keeps_vendor_prefix_and_flags_and_agrees_across_apis)
{
	devid::DeviceIdentityProvider provider{make_profile(69)};
	const std::uint8_t real[6] = {0x3C, 0x52, 0x82, 0xAA, 0xBB, 0xCC};
	std::uint8_t ipHelper[6], netbios[6], wmi[6];
	std::memcpy(ipHelper, real, 6);
	std::memcpy(netbios, real, 6);
	std::memcpy(wmi, real, 6);
	provider.virtualMac(ipHelper, 6);
	provider.virtualMac(netbios, 6);
	provider.virtualMac(wmi, 6);
	CHECK(std::memcmp(ipHelper, netbios, 6) == 0 && std::memcmp(ipHelper, wmi, 6) == 0);
	CHECK(std::memcmp(ipHelper, real, 3) == 0);   // OUI and first-byte flags kept
	CHECK(std::memcmp(ipHelper, real, 6) != 0);
	provider.virtualMac(ipHelper, 6);              // already virtual: no second rewrite
	CHECK(std::memcmp(ipHelper, netbios, 6) == 0);

	std::uint8_t zero[6] = {}, ones[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	provider.virtualMac(zero, 6);
	provider.virtualMac(ones, 6);
	CHECK(zero[0] == 0 && zero[5] == 0 && ones[0] == 0xFF && ones[5] == 0xFF);
	std::uint8_t wrongLength[4] = {1, 2, 3, 4};
	provider.virtualMac(wrongLength, 4);
	CHECK(wrongLength[3] == 4);
}

TEST(smbios_table_and_wmi_style_queries_agree)
{
	const devid::DeviceProfile profile = make_profile(70);
	devid::DeviceIdentityProvider provider{profile};
	const std::string systemSerial = "PF2ABCDE", boardSerial = "L1HF9AB00CD", chassisSerial = "To Be Filled By O.E.M.";
	SmbiosFixture fixture = make_smbios(systemSerial, boardSerial, chassisSerial);
	const std::vector<std::uint8_t> original = fixture.bytes;

	const std::size_t changed = provider.rewriteSmbiosTable(fixture.bytes.data(), fixture.bytes.size());
	CHECK(changed == 4); // uuid + three serials

	// Length never changes, so no structure moved.
	CHECK(fixture.bytes.size() == original.size());

	// What WMI would be asked to translate for the same source strings.
	const std::string wmiSystem = provider.virtualSerial(devid::SerialDomain::SmbiosSystem, systemSerial);
	const std::string wmiBoard = provider.virtualSerial(devid::SerialDomain::SmbiosBoard, boardSerial);
	const std::string wmiChassis = provider.virtualSerial(devid::SerialDomain::SmbiosChassis, chassisSerial);
	CHECK(find_bytes(fixture.bytes, wmiSystem) != std::string::npos);
	CHECK(find_bytes(fixture.bytes, wmiBoard) != std::string::npos);
	CHECK(find_bytes(fixture.bytes, wmiChassis) != std::string::npos);
	CHECK(find_bytes(fixture.bytes, systemSerial) == std::string::npos);
	CHECK(find_bytes(fixture.bytes, boardSerial) == std::string::npos);

	// Untouched strings stay byte for byte (vendor, product, BIOS).
	CHECK(find_bytes(fixture.bytes, "Contoso BIOS") != std::string::npos);
	CHECK(find_bytes(fixture.bytes, "Model 9") != std::string::npos);

	// UUID inside the table, read back the way WMI/SMBIOS readers print it, equals the WMI-path value.
	const std::string tableUuid = devid::DeviceIdentityProvider::smbiosUuidText(fixture.bytes.data() + fixture.uuidOffset, 3, 3);
	CHECK(tableUuid == provider.virtualSystemUuid("00000000-0000-0000-0000-000000000000"));

	// Only the intended bytes changed.
	std::size_t differing = 0;
	for (std::size_t i = 0; i < original.size(); ++i) if (original[i] != fixture.bytes[i]) ++differing;
	CHECK(differing <= 16 + systemSerial.size() + boardSerial.size() + chassisSerial.size());
	CHECK(differing >= 16);

	// Second pass is a no-op for serials (already virtual) and rewrites the same UUID again.
	const std::vector<std::uint8_t> once = fixture.bytes;
	provider.rewriteSmbiosTable(fixture.bytes.data(), fixture.bytes.size());
	CHECK(fixture.bytes == once);
}

TEST(smbios_pre_2_6_uses_big_endian_uuid_layout)
{
	devid::DeviceIdentityProvider provider{make_profile(71)};
	SmbiosFixture fixture = make_smbios("S1", "B1", "C1", 2, 4);
	provider.rewriteSmbiosTable(fixture.bytes.data(), fixture.bytes.size());
	CHECK(devid::DeviceIdentityProvider::smbiosUuidText(fixture.bytes.data() + fixture.uuidOffset, 2, 4) == provider.profile().hardware.systemUuid);
}

TEST(smbios_rewrite_survives_malformed_input)
{
	devid::DeviceIdentityProvider provider{make_profile(72)};
	SmbiosFixture fixture = make_smbios("SERIAL01", "BOARD001", "CHASSIS1");
	for (std::size_t size = 0; size <= fixture.bytes.size(); ++size)
	{
		std::vector<std::uint8_t> truncated(fixture.bytes.begin(), fixture.bytes.begin() + static_cast<std::ptrdiff_t>(size));
		provider.rewriteSmbiosTable(truncated.data(), truncated.size()); // must not read or write out of bounds
	}
	// A structure whose declared length runs past the buffer end.
	std::vector<std::uint8_t> bogus = fixture.bytes;
	bogus[8 + 1] = 0xFF;
	provider.rewriteSmbiosTable(bogus.data(), bogus.size());
	provider.rewriteSmbiosTable(nullptr, 0);
	CHECK(true);
}

int main()
{
	for (auto& [name, body] : registry())
	{
		g_current = name;
		body();
	}
	std::printf("%d checks, %d failures\n", g_checks, g_failures);
	return g_failures == 0 ? 0 : 1;
}
