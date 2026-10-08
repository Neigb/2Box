#pragma once

// Launch-time configuration: whether device simulation is on and which data domains it covers.
// Isolation hooks (plain multi-instance behaviour) are always installed.
// Decided by the host once per launch, serialised into the injection payload, and forwarded
// verbatim to child processes. The injected DLL never reads environment variables or files for this.
//
// Default (no policy rule) == plain multi-instance isolation:
// capabilities == 0 and the payload carries no device profile.

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "DeviceProfile.hpp"
#include "InstanceIdentity.hpp"

namespace devid
{
	// Domain capabilities say *what* data is simulated; every API that exposes that data is covered
	// together, or none is. Transport capabilities only widen how a domain is reached.
	enum Capability : std::uint32_t
	{
		kCapNone = 0,
		kCapStorage = 1u << 0,      // DeviceIoControl SMART / SCSI miniport / storage descriptor serials
		kCapNetwork = 1u << 1,      // IP Helper + NetBIOS: MAC, adapter GUID
		kCapSmbios = 1u << 2,       // GetSystemFirmwareTable('RSMB'): system UUID, system/board/chassis serials
		kCapWmi = 1u << 3,          // transport: WMI results for the enabled domains
		kCapStorageAsync = 1u << 4, // overlapped completion (GetOverlappedResult / completion ports); implied by `storage`
		kCapStorageWait = 1u << 5,  // transport, experimental: wait-based completion (hooks WaitFor* / CloseHandle)
		kCapOs = 1u << 6,           // registry reads of MachineGuid (heuristic: by value name and GUID shape)
	};

	inline constexpr std::uint32_t kDomainCaps = kCapStorage | kCapNetwork | kCapSmbios | kCapOs;
	inline constexpr std::uint32_t kAllCaps = kDomainCaps | kCapWmi | kCapStorageAsync | kCapStorageWait;

	struct LaunchConfig
	{
		std::uint64_t sessionId{0};
		std::uint64_t objectNamespaceId{0};
		std::uint32_t capabilities{kCapNone};
		std::optional<DeviceProfile> profile;

		bool deviceSimulationEnabled() const { return (capabilities & kDomainCaps) != 0; }
	};

	// Make a capability mask self-consistent: transports need the domain they transport, and a simulated
	// storage domain always covers overlapped I/O too (otherwise a synchronous query would be rewritten and the
	// same query issued with an OVERLAPPED would not).
	inline std::uint32_t normalize_capabilities(std::uint32_t caps)
	{
		caps &= kAllCaps;
		if (caps & (kCapStorageAsync | kCapStorageWait)) caps |= kCapStorage;
		if (caps & kCapStorage) caps |= kCapStorageAsync;
		if ((caps & kDomainCaps) == 0) caps = kCapNone; // transports alone simulate nothing
		return caps;
	}

	struct HookPlan
	{
		bool storage{false};
		bool storageAsync{false};
		bool storageWait{false};
		bool network{false};
		bool wmi{false};
		bool smbios{false};
		bool os{false};
	};

	inline HookPlan make_hook_plan(const LaunchConfig& config)
	{
		HookPlan plan;
		const std::uint32_t caps = normalize_capabilities(config.capabilities);
		plan.storage = (caps & kCapStorage) != 0;
		plan.storageAsync = plan.storage && (caps & kCapStorageAsync) != 0;
		plan.storageWait = plan.storage && (caps & kCapStorageWait) != 0;
		plan.network = (caps & kCapNetwork) != 0;
		plan.smbios = (caps & kCapSmbios) != 0;
		plan.os = (caps & kCapOs) != 0;
		plan.wmi = (caps & kCapWmi) != 0; // normalized: only set when some domain is enabled
		return plan;
	}

	// --- capability names ------------------------------------------------------------------------

	inline std::optional<std::uint32_t> capability_from_name(std::string_view name)
	{
		if (name == "storage") return kCapStorage;
		if (name == "network") return kCapNetwork;
		if (name == "smbios") return kCapSmbios;
		if (name == "os") return kCapOs;
		if (name == "wmi") return kCapWmi;
		if (name == "storage-async") return kCapStorageAsync;
		if (name == "storage-wait") return kCapStorageWait;
		return std::nullopt;
	}

	namespace detail
	{
		inline std::string_view trim(std::string_view text)
		{
			const auto space = [](char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; };
			while (!text.empty() && space(text.front())) text.remove_prefix(1);
			while (!text.empty() && space(text.back())) text.remove_suffix(1);
			return text;
		}

		inline std::string lower_path(std::string_view text)
		{
			std::string result{text};
			for (char& c : result)
			{
				c = c == '/' ? '\\' : ascii_lower(c);
			}
			return result;
		}
	}

	// --- per-application policy ------------------------------------------------------------------

	struct PolicyRule
	{
		std::string match; // normalised: lower-case, backslashes
		std::uint32_t capabilities{kCapNone};
	};

	struct DevicePolicy
	{
		std::vector<PolicyRule> rules;
		std::vector<std::string> errors; // one message per rejected line; callers should fail loudly

		// First matching rule wins. A match without a path separator compares the file name only.
		std::uint32_t resolve(std::string_view exePath) const
		{
			const std::string path = detail::lower_path(exePath);
			const std::size_t slash = path.rfind('\\');
			const std::string_view fileName = slash == std::string::npos ? std::string_view{path}
				: std::string_view{path}.substr(slash + 1);
			for (const PolicyRule& rule : rules)
			{
				const bool hasSeparator = rule.match.find('\\') != std::string::npos;
				if (hasSeparator ? rule.match == path : rule.match == fileName) return rule.capabilities;
			}
			return kCapNone;
		}
	};

	// Format:
	//   [app]
	//   match = target.exe          ; file name, or a full path
	//   capabilities = storage, network, smbios, wmi
	// '#' and ';' start comments (at a line start or after whitespace). An unknown capability or a rule without `match` rejects the rule
	// and records an error.
	inline DevicePolicy parse_policy(std::string_view text)
	{
		DevicePolicy policy;
		struct Pending
		{
			bool open{false};
			std::string match;
			std::uint32_t caps{kCapNone};
			bool bad{false};
			std::size_t line{0};
		} pending;
		const auto flush = [&]
		{
			if (!pending.open) return;
			if (!pending.bad)
			{
				if (pending.match.empty())
					policy.errors.push_back("line " + std::to_string(pending.line) + ": [app] has no match");
				else
					policy.rules.push_back(PolicyRule{detail::lower_path(pending.match), normalize_capabilities(pending.caps)});
			}
			pending = Pending{};
		};
		std::size_t lineNumber = 0, pos = 0;
		while (pos <= text.size())
		{
			std::size_t end = text.find('\n', pos);
			if (end == std::string_view::npos) end = text.size();
			std::string_view line = text.substr(pos, end - pos);
			pos = end + 1;
			++lineNumber;
			// A comment starts at a line start or after whitespace, so paths may contain '#' or ';'.
			for (std::size_t i = 0; i < line.size(); ++i)
			{
				if ((line[i] == '#' || line[i] == ';') && (i == 0 || line[i - 1] == ' ' || line[i - 1] == '\t'))
				{
					line = line.substr(0, i);
					break;
				}
			}
			line = detail::trim(line);
			if (line.empty()) continue;
			if (line == "[app]")
			{
				flush();
				pending.open = true;
				pending.line = lineNumber;
				continue;
			}
			const std::size_t equals = line.find('=');
			if (!pending.open || equals == std::string_view::npos)
			{
				policy.errors.push_back("line " + std::to_string(lineNumber) + ": unexpected text");
				continue;
			}
			const std::string_view key = detail::trim(line.substr(0, equals));
			const std::string_view value = detail::trim(line.substr(equals + 1));
			if (key == "match")
			{
				pending.match.assign(value);
			}
			else if (key == "capabilities")
			{
				std::size_t start = 0;
				while (start <= value.size())
				{
					std::size_t comma = value.find(',', start);
					if (comma == std::string_view::npos) comma = value.size();
					const std::string_view name = detail::trim(value.substr(start, comma - start));
					start = comma + 1;
					if (name.empty()) continue;
					if (const auto cap = capability_from_name(name)) pending.caps |= *cap;
					else
					{
						policy.errors.push_back("line " + std::to_string(lineNumber) + ": unknown capability '" + std::string{name} + "'");
						pending.bad = true;
					}
				}
			}
			else
			{
				policy.errors.push_back("line " + std::to_string(lineNumber) + ": unknown key '" + std::string{key} + "'");
				pending.bad = true;
			}
		}
		flush();
		return policy;
	}

	// --- payload encoding ------------------------------------------------------------------------

	inline constexpr std::string_view kLaunchMagic = "launch-config";
	inline constexpr std::uint32_t kLaunchVersion = 1;

	inline std::string encode_launch_config(const LaunchConfig& config)
	{
		std::string text;
		text += std::string{kLaunchMagic} + ' ' + std::to_string(kLaunchVersion) + '\n';
		text += "session=" + detail::hex16(config.sessionId) + '\n';
		text += "namespace=" + detail::hex16(config.objectNamespaceId) + '\n';
		text += "caps=" + std::to_string(normalize_capabilities(config.capabilities)) + '\n';
		if (config.profile)
		{
			text += "profile:\n";
			text += serialize_profile(*config.profile);
		}
		return text;
	}

	struct LaunchDecodeResult
	{
		std::optional<LaunchConfig> config;
		std::string error;
	};

	inline LaunchDecodeResult decode_launch_config(std::string_view text)
	{
		const auto fail = [](std::string message) { return LaunchDecodeResult{std::nullopt, std::move(message)}; };
		LaunchConfig config;
		bool sawMagic = false, hasSession = false, hasNamespace = false, hasCaps = false;
		std::size_t pos = 0;
		while (pos < text.size())
		{
			std::size_t end = text.find('\n', pos);
			if (end == std::string_view::npos) end = text.size();
			std::string_view line = text.substr(pos, end - pos);
			const std::size_t next = end + 1;
			if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
			if (line.empty()) { pos = next; continue; }
			if (!sawMagic)
			{
				if (line != std::string{kLaunchMagic} + ' ' + std::to_string(kLaunchVersion))
					return fail("unsupported launch config");
				sawMagic = true;
				pos = next;
				continue;
			}
			if (line == "profile:")
			{
				ProfileParseResult parsed = parse_profile(next < text.size() ? text.substr(next) : std::string_view{});
				if (!parsed.profile) return fail("launch config profile: " + parsed.error);
				config.profile = std::move(parsed.profile);
				pos = text.size();
				break;
			}
			const std::size_t equals = line.find('=');
			if (equals == std::string_view::npos) return fail("malformed launch config line");
			const std::string_view key = line.substr(0, equals);
			const std::string_view value = line.substr(equals + 1);
			if (key == "session")
			{
				const auto parsed = detail::parse_hex64(value);
				if (!parsed) return fail("invalid session");
				config.sessionId = *parsed;
				hasSession = true;
			}
			else if (key == "namespace")
			{
				const auto parsed = detail::parse_hex64(value);
				if (!parsed) return fail("invalid namespace");
				config.objectNamespaceId = *parsed;
				hasNamespace = true;
			}
			else if (key == "caps")
			{
				const auto parsed = detail::parse_dec64(value);
				if (!parsed || *parsed > 0xFFFFFFFFULL) return fail("invalid caps");
				config.capabilities = static_cast<std::uint32_t>(*parsed);
				hasCaps = true;
			}
			else return fail("unknown launch config key");
			pos = next;
		}
		if (!(sawMagic && hasSession && hasNamespace && hasCaps)) return fail("incomplete launch config");
		if (config.capabilities != normalize_capabilities(config.capabilities)) return fail("inconsistent capabilities");
		// Invariant: simulation without a profile (or a profile without simulation) is a host bug.
		if (config.deviceSimulationEnabled() != config.profile.has_value()) return fail("capabilities and profile disagree");
		return LaunchDecodeResult{std::move(config), {}};
	}
}
