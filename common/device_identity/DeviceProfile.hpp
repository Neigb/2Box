#pragma once

// Persistent device profile: the data that makes a test environment look like a stable machine.
// Pure standard C++ (no Windows headers) so it can be unit tested on any platform.
// Nothing in this file refers to InstanceIdentity.

#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#include "InstanceIdentity.hpp"

namespace devid
{
	inline constexpr std::uint32_t kProfileSchemaVersion = 1;

	namespace detail
	{
		inline constexpr std::uint64_t kFnvOffset = 14695981039346656037ULL;
		inline constexpr std::uint64_t kFnvPrime = 1099511628211ULL;

		inline std::uint64_t fnv1a64(std::string_view data, std::uint64_t seed = kFnvOffset)
		{
			std::uint64_t hash = seed;
			for (const unsigned char c : data)
			{
				hash = (hash ^ c) * kFnvPrime;
			}
			return hash;
		}

		inline std::uint64_t splitmix64(std::uint64_t& state)
		{
			state += 0x9E3779B97F4A7C15ULL;
			std::uint64_t z = state;
			z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
			z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
			return z ^ (z >> 31);
		}

		// Deterministic keyed stream: the same (salt, domain, key) always yields the same sequence.
		// Not cryptographic on purpose; a profile is test data, not a secret.
		class KeyedStream
		{
		public:
			KeyedStream(std::uint64_t salt, std::uint64_t domainTag, std::string_view key)
			{
				m_state = fnv1a64(key, kFnvOffset ^ salt ^ (domainTag * 0x9E3779B97F4A7C15ULL));
				splitmix64(m_state);
				splitmix64(m_state);
			}

			std::uint64_t next() { return splitmix64(m_state); }
			std::uint32_t below(std::uint32_t bound) { return static_cast<std::uint32_t>(next() % bound); }

		private:
			std::uint64_t m_state{0};
		};

		inline char ascii_upper(char c) { return c >= 'a' && c <= 'z' ? static_cast<char>(c - 'a' + 'A') : c; }
		inline char ascii_lower(char c) { return c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : c; }

		inline int hex_value(char c)
		{
			if (c >= '0' && c <= '9') return c - '0';
			if (c >= 'A' && c <= 'F') return c - 'A' + 10;
			if (c >= 'a' && c <= 'f') return c - 'a' + 10;
			return -1;
		}

		inline std::optional<std::uint64_t> parse_hex64(std::string_view text)
		{
			if (text.empty() || text.size() > 16) return std::nullopt;
			std::uint64_t value = 0;
			for (const char c : text)
			{
				const int digit = hex_value(c);
				if (digit < 0) return std::nullopt;
				value = (value << 4) | static_cast<std::uint64_t>(digit);
			}
			return value;
		}

		inline std::optional<std::uint64_t> parse_dec64(std::string_view text)
		{
			if (text.empty() || text.size() > 20) return std::nullopt;
			std::uint64_t value = 0;
			for (const char c : text)
			{
				if (c < '0' || c > '9') return std::nullopt;
				value = value * 10 + static_cast<std::uint64_t>(c - '0');
			}
			return value;
		}

		inline std::string format_guid(const std::array<std::uint8_t, 16>& bytes, bool upper)
		{
			const char* digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
			std::string result;
			result.reserve(36);
			for (std::size_t i = 0; i < bytes.size(); ++i)
			{
				if (i == 4 || i == 6 || i == 8 || i == 10) result.push_back('-');
				result.push_back(digits[bytes[i] >> 4]);
				result.push_back(digits[bytes[i] & 0xF]);
			}
			return result;
		}

		// RFC 4122 version 4 / variant 1 layout.
		inline std::array<std::uint8_t, 16> make_v4_guid_bytes(std::uint64_t high, std::uint64_t low)
		{
			std::array<std::uint8_t, 16> bytes{};
			for (std::size_t i = 0; i < 8; ++i)
			{
				bytes[i] = static_cast<std::uint8_t>(high >> (56 - i * 8));
				bytes[8 + i] = static_cast<std::uint8_t>(low >> (56 - i * 8));
			}
			bytes[6] = static_cast<std::uint8_t>((bytes[6] & 0x0F) | 0x40);
			bytes[8] = static_cast<std::uint8_t>((bytes[8] & 0x3F) | 0x80);
			return bytes;
		}

		inline std::string path_to_utf8(const std::filesystem::path& path)
		{
			const auto text = path.u8string();
			return std::string(reinterpret_cast<const char*>(text.data()), text.size());
		}
	}

	struct StorageProfile
	{
		std::uint64_t salt{0};
		bool operator==(const StorageProfile&) const = default;
	};

	struct NetworkProfile
	{
		std::uint64_t salt{0};
		bool operator==(const NetworkProfile&) const = default;
	};

	struct OsProfile
	{
		// Lower-case, hyphenated, no braces: the registry's MachineGuid shape.
		// Consumer (registry read path) is not implemented yet; see docs.
		std::string machineGuid;
		bool operator==(const OsProfile&) const = default;
	};

	struct HardwareProfile
	{
		std::uint64_t salt{0};
		// Upper-case, hyphenated, no braces: the shape WMI prints for Win32_ComputerSystemProduct.UUID.
		std::string systemUuid;
		bool operator==(const HardwareProfile&) const = default;
	};

	struct DeviceProfile
	{
		std::uint32_t schemaVersion{kProfileSchemaVersion};
		std::uint64_t profileId{0};
		StorageProfile storage;
		NetworkProfile network;
		OsProfile os;
		HardwareProfile hardware;
		bool operator==(const DeviceProfile&) const = default;
	};

	// Generate a brand-new profile. `rng` returns uint64_t; pass a CSPRNG-seeded source in production
	// and a fixed-seed one in tests. Call this once per profile and persist the result immediately.
	template <typename Rng>
	DeviceProfile generate_profile(Rng&& rng)
	{
		const auto nonZero = [&]
		{
			std::uint64_t value = 0;
			while (value == 0) value = static_cast<std::uint64_t>(rng());
			return value;
		};
		DeviceProfile profile;
		profile.profileId = nonZero();
		profile.storage.salt = nonZero();
		profile.network.salt = nonZero();
		profile.hardware.salt = nonZero();
		profile.hardware.systemUuid = detail::format_guid(detail::make_v4_guid_bytes(nonZero(), nonZero()), true);
		profile.os.machineGuid = detail::format_guid(detail::make_v4_guid_bytes(nonZero(), nonZero()), false);
		return profile;
	}

	inline constexpr std::string_view kProfileMagic = "device-profile";

	inline std::string serialize_profile(const DeviceProfile& profile)
	{
		std::string body;
		body += std::string{kProfileMagic} + ' ' + std::to_string(profile.schemaVersion) + '\n';
		body += "profile_id=" + detail::hex16(profile.profileId) + '\n';
		body += "storage.salt=" + detail::hex16(profile.storage.salt) + '\n';
		body += "network.salt=" + detail::hex16(profile.network.salt) + '\n';
		body += "hardware.salt=" + detail::hex16(profile.hardware.salt) + '\n';
		body += "hardware.system_uuid=" + profile.hardware.systemUuid + '\n';
		body += "os.machine_guid=" + profile.os.machineGuid + '\n';
		body += "check=" + detail::hex16(detail::fnv1a64(body)) + '\n';
		return body;
	}

	struct ProfileParseResult
	{
		std::optional<DeviceProfile> profile;
		std::string error;
	};

	inline ProfileParseResult parse_profile(std::string_view text)
	{
		const auto fail = [](std::string message) { return ProfileParseResult{std::nullopt, std::move(message)}; };
		DeviceProfile profile;
		bool sawMagic = false;
		std::optional<std::uint64_t> check;
		std::size_t checkLineStart = std::string_view::npos;
		bool hasId = false, hasStorage = false, hasNetwork = false, hasHardware = false, hasUuid = false, hasGuid = false;

		std::size_t pos = 0;
		while (pos < text.size())
		{
			const std::size_t lineStart = pos;
			std::size_t lineEnd = text.find('\n', pos);
			if (lineEnd == std::string_view::npos) lineEnd = text.size();
			pos = lineEnd + 1;
			std::string_view line = text.substr(lineStart, lineEnd - lineStart);
			if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
			if (line.empty()) continue;

			if (!sawMagic)
			{
				if (!line.starts_with(kProfileMagic) || line.size() <= kProfileMagic.size() + 1
					|| line[kProfileMagic.size()] != ' ')
					return fail("not a device profile");
				const auto version = detail::parse_dec64(line.substr(kProfileMagic.size() + 1));
				if (!version) return fail("invalid profile version");
				if (*version != kProfileSchemaVersion)
					return fail("unsupported profile schema version " + std::to_string(*version));
				profile.schemaVersion = static_cast<std::uint32_t>(*version);
				sawMagic = true;
				continue;
			}
			const std::size_t equals = line.find('=');
			if (equals == std::string_view::npos) return fail("malformed profile line");
			const std::string_view key = line.substr(0, equals);
			const std::string_view value = line.substr(equals + 1);
			if (key == "check")
			{
				check = detail::parse_hex64(value);
				checkLineStart = lineStart;
				break;
			}
			if (key == "profile_id")
			{
				const auto parsed = detail::parse_hex64(value);
				if (!parsed || *parsed == 0) return fail("invalid profile_id");
				profile.profileId = *parsed;
				hasId = true;
			}
			else if (key == "storage.salt" || key == "network.salt" || key == "hardware.salt")
			{
				const auto parsed = detail::parse_hex64(value);
				if (!parsed || *parsed == 0) return fail("invalid " + std::string{key});
				if (key == "storage.salt") { profile.storage.salt = *parsed; hasStorage = true; }
				else if (key == "network.salt") { profile.network.salt = *parsed; hasNetwork = true; }
				else { profile.hardware.salt = *parsed; hasHardware = true; }
			}
			else if (key == "hardware.system_uuid" || key == "os.machine_guid")
			{
				if (value.size() != 36) return fail("invalid " + std::string{key});
				for (std::size_t i = 0; i < value.size(); ++i)
				{
					const bool dash = i == 8 || i == 13 || i == 18 || i == 23;
					if (dash ? value[i] != '-' : detail::hex_value(value[i]) < 0) return fail("invalid " + std::string{key});
				}
				if (key == "hardware.system_uuid") { profile.hardware.systemUuid = value; hasUuid = true; }
				else { profile.os.machineGuid = value; hasGuid = true; }
			}
			// Unknown keys inside the same schema version are ignored but still covered by the checksum.
		}
		if (!sawMagic) return fail("empty profile");
		if (!check || checkLineStart == std::string_view::npos) return fail("missing checksum");
		if (detail::fnv1a64(text.substr(0, checkLineStart)) != *check) return fail("profile checksum mismatch");
		if (!(hasId && hasStorage && hasNetwork && hasHardware && hasUuid && hasGuid)) return fail("profile is missing fields");
		return ProfileParseResult{profile, {}};
	}

	// Directory of profile files, one file per profile id. A profile outlives process restarts and is
	// only ever created explicitly; a missing or damaged file is an error, never a silent regeneration.
	class DeviceProfileStore
	{
	public:
		explicit DeviceProfileStore(std::filesystem::path directory) : m_directory(std::move(directory)) {}

		std::filesystem::path pathFor(std::uint64_t profileId) const
		{
			return m_directory / (detail::hex16(profileId) + ".profile");
		}

		ProfileParseResult load(std::uint64_t profileId) const
		{
			const std::filesystem::path path = pathFor(profileId);
			std::ifstream file{path, std::ios::binary};
			if (!file) return {std::nullopt, "device profile not found: " + detail::path_to_utf8(path)};
			std::string text{std::istreambuf_iterator<char>{file}, std::istreambuf_iterator<char>{}};
			ProfileParseResult result = parse_profile(text);
			if (result.profile && result.profile->profileId != profileId)
				return {std::nullopt, "device profile id does not match its file name: " + detail::path_to_utf8(path)};
			if (!result.profile) result.error += ": " + detail::path_to_utf8(path);
			return result;
		}

		// Returns an empty string on success.
		std::string save(const DeviceProfile& profile) const
		{
			std::error_code ec;
			std::filesystem::create_directories(m_directory, ec);
			if (ec) return "cannot create profile directory: " + detail::path_to_utf8(m_directory);
			const std::filesystem::path path = pathFor(profile.profileId);
			std::filesystem::path temp = path;
			temp += ".tmp";
			{
				std::ofstream file{temp, std::ios::binary | std::ios::trunc};
				if (!file) return "cannot write device profile: " + detail::path_to_utf8(temp);
				const std::string text = serialize_profile(profile);
				file.write(text.data(), static_cast<std::streamsize>(text.size()));
				file.flush();
				if (!file) return "cannot write device profile: " + detail::path_to_utf8(temp);
			}
			std::filesystem::rename(temp, path, ec);
			if (ec)
			{
				std::filesystem::remove(temp, ec);
				return "cannot publish device profile: " + detail::path_to_utf8(path);
			}
			return {};
		}

		void remove(std::uint64_t profileId) const noexcept
		{
			std::error_code ec;
			std::filesystem::remove(pathFor(profileId), ec);
		}

	private:
		std::filesystem::path m_directory;
	};

	// Return the profile bound to an environment, creating and binding one exactly once if none is bound.
	// `boundId == 0` means "not bound yet". `bind(id)` persists the binding (e.g. a registry value).
	// A bound-but-unreadable profile throws: regenerating would silently turn the environment into a new machine.
	template <typename Rng, typename Bind>
	DeviceProfile obtain_profile(const DeviceProfileStore& store, std::uint64_t boundId, Rng&& rng, Bind&& bind)
	{
		if (boundId != 0)
		{
			ProfileParseResult loaded = store.load(boundId);
			if (!loaded.profile) throw std::runtime_error(loaded.error);
			return *loaded.profile;
		}
		DeviceProfile profile = generate_profile(rng);
		if (const std::string error = store.save(profile); !error.empty()) throw std::runtime_error(error);
		try
		{
			bind(profile.profileId);
		}
		catch (...)
		{
			store.remove(profile.profileId);
			throw;
		}
		return profile;
	}
}
