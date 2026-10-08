#pragma once

// DeviceIdentityProvider: read-only mapping from "what the host really reports" to "what this
// device profile reports". Constructed from a DeviceProfile only - it cannot see an InstanceIdentity.
//
// Strategy (see docs/device-identity-architecture.md):
//  * singletons that do not depend on host hardware are stored in the profile (system UUID);
//  * per-device values are derived from (profile salt, domain, source value) and keep the *shape*
//    of the source (length, character classes, separators, case, short vendor tags), so the
//    untouched vendor/model fields stay plausible and every API that sees the same source value
//    produces the same result;
//  * derivation is stateless; the only state is a small alias table that makes re-feeding an
//    already virtual value a no-op.

#include <array>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>

#include "DeviceProfile.hpp"

namespace devid
{
	enum class SerialDomain : std::uint8_t
	{
		Disk,
		SmbiosSystem,
		SmbiosBoard,
		SmbiosChassis,
		PnpStorageInstance,
		PnpNetworkInstance,
	};

	namespace detail
	{
		inline bool is_digit(char c) { return c >= '0' && c <= '9'; }
		inline bool is_upper(char c) { return c >= 'A' && c <= 'Z'; }
		inline bool is_lower(char c) { return c >= 'a' && c <= 'z'; }
		inline bool is_alnum(char c) { return is_digit(c) || is_upper(c) || is_lower(c); }

		inline bool equals_ignore_case(std::string_view a, std::string_view b)
		{
			if (a.size() != b.size()) return false;
			for (std::size_t i = 0; i < a.size(); ++i)
			{
				if (ascii_lower(a[i]) != ascii_lower(b[i])) return false;
			}
			return true;
		}

		// Values that carry no identity ("To Be Filled By O.E.M." ...). Deriving from the text itself
		// would produce gibberish, so they are replaced by a generated serial of the same length.
		inline bool is_placeholder_serial(std::string_view value)
		{
			static constexpr std::array<std::string_view, 12> known = {
				"to be filled by o.e.m.", "to be filled by oem", "default string", "none", "not specified",
				"not applicable", "system serial number", "chassis serial number", "base board serial number",
				"n/a", "unknown", "o.e.m."
			};
			for (const std::string_view item : known)
			{
				if (equals_ignore_case(value, item)) return true;
			}
			if (value.size() >= 2 && value.find_first_not_of(value.front()) == std::string_view::npos) return true;
			return false;
		}

		inline std::string generic_serial(KeyedStream& stream, std::size_t length)
		{
			static constexpr std::string_view alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ0123456789";
			std::string result(length, '0');
			for (char& c : result) c = alphabet[stream.below(static_cast<std::uint32_t>(alphabet.size()))];
			return result;
		}

		inline char random_in_class(KeyedStream& stream, char like)
		{
			if (is_digit(like)) return static_cast<char>('0' + stream.below(10));
			if (is_upper(like)) return static_cast<char>('A' + stream.below(26));
			return static_cast<char>('a' + stream.below(26));
		}

		// Only the alphanumeric content identifies a device ("0025_38B1_21A2_3C4D." and "002538B121A23C4D" are
		// the same NVMe serial in two spellings), so keys and random draws ignore separators.
		inline std::string alnum_only(std::string_view source)
		{
			std::string result;
			for (const char c : source)
			{
				if (is_alnum(c)) result.push_back(c);
			}
			return result;
		}

		// Replace every alphanumeric character with a random one of the same class; separators never change.
		// If the whole content looks hexadecimal (digits and A-F, both present) it stays hexadecimal in every
		// spelling. A leading short alphabetic vendor tag ending in '-' ("WD-") is kept.
		inline std::string shape_preserving(std::string_view source, KeyedStream& stream)
		{
			std::string out{source};
			const std::size_t n = out.size();
			std::size_t tagEnd = 0;
			{
				std::size_t k = 0;
				while (k < n && k < 5 && is_alnum(out[k]) && !is_digit(out[k])) ++k;
				if (k >= 1 && k <= 4 && k < n && out[k] == '-') tagEnd = k + 1;
			}
			bool allHex = true, hasDigit = false, hasHexLetter = false, hasLower = false;
			for (std::size_t i = tagEnd; i < n; ++i)
			{
				const char c = out[i];
				if (!is_alnum(c)) continue;
				if (hex_value(c) < 0) allHex = false;
				if (is_digit(c)) hasDigit = true;
				else if (hex_value(c) >= 0) hasHexLetter = true;
				if (is_lower(c)) hasLower = true;
			}
			const bool hex = allHex && hasDigit && hasHexLetter;
			const char* digits = hasLower ? "0123456789abcdef" : "0123456789ABCDEF";
			for (std::size_t i = tagEnd; i < n; ++i)
			{
				if (!is_alnum(out[i])) continue;
				out[i] = hex ? digits[stream.below(16)] : random_in_class(stream, out[i]);
			}
			return out;
		}

		// Guarantee a derived value differs from its source (deterministically).
		inline void ensure_different(std::string& derived, std::string_view source)
		{
			if (derived != source) return;
			for (std::size_t i = derived.size(); i-- > 0;)
			{
				char& c = derived[i];
				if (is_digit(c)) { c = c == '9' ? '0' : static_cast<char>(c + 1); return; }
				if (is_upper(c)) { c = c == 'Z' ? 'A' : static_cast<char>(c + 1); return; }
				if (is_lower(c)) { c = c == 'z' ? 'a' : static_cast<char>(c + 1); return; }
			}
		}

		struct GuidText
		{
			bool wrapped{false};
			bool lower{false};
			std::string upper; // 36 chars, upper-case hex, hyphenated, no braces
		};

		inline std::optional<GuidText> parse_guid_text(std::string_view text)
		{
			GuidText guid;
			if (text.size() == 38 && text.front() == '{' && text.back() == '}')
			{
				guid.wrapped = true;
				text = text.substr(1, 36);
			}
			if (text.size() != 36) return std::nullopt;
			guid.upper.assign(text);
			for (std::size_t i = 0; i < guid.upper.size(); ++i)
			{
				char& c = guid.upper[i];
				if (i == 8 || i == 13 || i == 18 || i == 23)
				{
					if (c != '-') return std::nullopt;
				}
				else if (hex_value(c) < 0) return std::nullopt;
				else if (is_lower(c)) { guid.lower = true; c = ascii_upper(c); }
			}
			return guid;
		}

		inline std::string render_guid(const GuidText& shape, std::string upper)
		{
			if (shape.lower) for (char& c : upper) c = ascii_lower(c);
			return shape.wrapped ? '{' + upper + '}' : upper;
		}

		inline std::array<std::uint8_t, 16> guid_text_to_bytes(std::string_view upperOrLower36)
		{
			std::array<std::uint8_t, 16> bytes{};
			std::size_t out = 0;
			for (std::size_t i = 0; i < upperOrLower36.size() && out < bytes.size();)
			{
				if (upperOrLower36[i] == '-') { ++i; continue; }
				bytes[out++] = static_cast<std::uint8_t>((hex_value(upperOrLower36[i]) << 4) | hex_value(upperOrLower36[i + 1]));
				i += 2;
			}
			return bytes;
		}
	}

	class DeviceIdentityProvider
	{
	public:
		explicit DeviceIdentityProvider(DeviceProfile profile) : m_profile(std::move(profile)) {}

		// A provider is tied to one profile; it must never be constructed from instance data.
		DeviceIdentityProvider(const DeviceIdentityProvider&) = delete;
		DeviceIdentityProvider& operator=(const DeviceIdentityProvider&) = delete;

		const DeviceProfile& profile() const { return m_profile; }

		// --- serials ---------------------------------------------------------------------------

		// Normalise a disk serial taken from any API: undo the ATA word swap, trim padding, upper-case.
		static std::string canonicalDiskSerial(std::string_view raw, bool ataWordOrder = false)
		{
			std::string value{raw};
			if (ataWordOrder)
			{
				for (std::size_t i = 0; i + 1 < value.size(); i += 2) std::swap(value[i], value[i + 1]);
			}
			const auto padding = [](char c) { return c == '\0' || c == ' ' || c == '\t'; };
			while (!value.empty() && padding(value.front())) value.erase(value.begin());
			while (!value.empty() && padding(value.back())) value.pop_back();
			for (char& c : value) c = detail::ascii_upper(c);
			return value;
		}

		// Virtual serial for `source` in `domain`. Same length as the (canonical) source.
		// Disk serials are returned in canonical form; the caller applies its own wire encoding
		// (ATA padding / word swap, trailing NULs ...).
		std::string virtualSerial(SerialDomain domain, std::string_view source, bool ataWordOrder = false) const
		{
			const bool disk = domain == SerialDomain::Disk;
			std::string key = disk ? canonicalDiskSerial(source, ataWordOrder) : std::string{source};
			if (key.empty()) return key;
			if (isVirtual(domain, key)) return key;

			detail::KeyedStream stream{saltFor(domain), 0x5345'5249'414CULL + static_cast<std::uint64_t>(domain), detail::alnum_only(key)};
			std::string result;
			const bool smbios = domain == SerialDomain::SmbiosSystem || domain == SerialDomain::SmbiosBoard
				|| domain == SerialDomain::SmbiosChassis;
			if (smbios && detail::is_placeholder_serial(key)) result = detail::generic_serial(stream, key.size());
			else result = detail::shape_preserving(key, stream);
			detail::ensure_different(result, key);
			remember(domain, result);
			return result;
		}

		// --- GUIDs -----------------------------------------------------------------------------

		// Network adapter GUID (IP Helper AdapterName, WMI GUID/SettingID). Accepts braces and either case;
		// anything that is not a GUID is returned unchanged.
		std::string virtualAdapterGuid(std::string_view source) const
		{
			const auto guid = detail::parse_guid_text(source);
			if (!guid) return std::string{source};
			if (isVirtualText(kAdapterGuidTag, guid->upper)) return std::string{source};
			detail::KeyedStream stream{m_profile.network.salt, 0x4755'4944ULL, guid->upper};
			std::string upper = detail::format_guid(detail::make_v4_guid_bytes(stream.next(), stream.next()), true);
			if (upper == guid->upper) upper[35] = upper[35] == '0' ? '1' : '0';
			rememberText(kAdapterGuidTag, upper);
			return detail::render_guid(*guid, std::move(upper));
		}

		// SMBIOS system UUID as WMI prints it. Independent of the host: always the profile's UUID.
		std::string virtualSystemUuid(std::string_view source) const
		{
			const auto guid = detail::parse_guid_text(source);
			if (!guid) return std::string{source};
			return detail::render_guid(*guid, m_profile.hardware.systemUuid);
		}

		// Registry MachineGuid: always the profile's value, written in the spelling (case, braces) of the source.
		std::string virtualMachineGuid(std::string_view source) const
		{
			const auto guid = detail::parse_guid_text(source);
			if (!guid) return std::string{source};
			const auto mine = detail::parse_guid_text(m_profile.os.machineGuid);
			return mine ? detail::render_guid(*guid, mine->upper) : std::string{source};
		}

		const std::string& machineGuid() const { return m_profile.os.machineGuid; }

		// --- MAC -------------------------------------------------------------------------------

		// Keeps the OUI and the unicast/local-admin bits (first three bytes) so the vendor stays consistent
		// with the untouched adapter description; replaces the NIC-specific half. All-zero and all-ones
		// addresses are not real NICs and are left alone.
		void virtualMac(std::uint8_t* address, std::size_t length) const
		{
			if (!address || length != 6) return;
			std::string key(reinterpret_cast<const char*>(address), 6);
			if (key == std::string(6, '\0') || key == std::string(6, '\xFF')) return;
			if (isVirtualText(kMacTag, key)) return;
			detail::KeyedStream stream{m_profile.network.salt, 0x4D41'43ULL, key};
			const std::uint64_t bits = stream.next();
			std::array<std::uint8_t, 6> result{address[0], address[1], address[2],
				static_cast<std::uint8_t>(bits), static_cast<std::uint8_t>(bits >> 8), static_cast<std::uint8_t>(bits >> 16)};
			if (std::memcmp(result.data(), address, 6) == 0) result[5] ^= 1;
			rememberText(kMacTag, std::string(reinterpret_cast<const char*>(result.data()), 6));
			std::memcpy(address, result.data(), 6);
		}

		// --- SMBIOS raw table (GetSystemFirmwareTable 'RSMB') -------------------------------------

		// Text form of an SMBIOS UUID, honouring the mixed-endian layout used since SMBIOS 2.6.
		static std::string smbiosUuidText(const std::uint8_t* uuid, unsigned major, unsigned minor)
		{
			std::array<std::uint8_t, 16> bytes{};
			std::memcpy(bytes.data(), uuid, 16);
			if (major > 2 || (major == 2 && minor >= 6))
			{
				std::swap(bytes[0], bytes[3]);
				std::swap(bytes[1], bytes[2]);
				std::swap(bytes[4], bytes[5]);
				std::swap(bytes[6], bytes[7]);
			}
			return detail::format_guid(bytes, true);
		}

		// Rewrites, in place and without changing any length, the system UUID and the system, board and
		// chassis serial strings of a RawSMBIOSData buffer. `size` is the number of valid bytes. Returns the
		// number of fields rewritten. Malformed input is left untouched from the first inconsistency on.
		std::size_t rewriteSmbiosTable(std::uint8_t* data, std::size_t size) const
		{
			if (!data || size < 8) return 0;
			const unsigned major = data[1], minor = data[2];
			const std::size_t declared = static_cast<std::size_t>(data[4]) | (static_cast<std::size_t>(data[5]) << 8)
				| (static_cast<std::size_t>(data[6]) << 16) | (static_cast<std::size_t>(data[7]) << 24);
			const std::size_t end = declared > size - 8 ? size : 8 + declared;
			std::size_t changed = 0;
			std::size_t pos = 8;
			while (pos + 4 <= end)
			{
				const std::uint8_t type = data[pos];
				const std::size_t formatted = data[pos + 1];
				if (formatted < 4 || pos + formatted > end) break;
				const std::size_t stringsStart = pos + formatted;
				std::size_t scan = stringsStart;
				std::size_t stringsEnd = stringsStart; // exclusive end of the string area, without terminators
				std::size_t next = 0;
				if (scan + 1 < end && data[scan] == 0 && data[scan + 1] == 0)
				{
					next = scan + 2;
				}
				else
				{
					while (scan + 1 < end && !(data[scan] == 0 && data[scan + 1] == 0)) ++scan;
					if (scan + 1 >= end) break;
					stringsEnd = scan;
					next = scan + 2;
				}

				const auto rewriteString = [&](std::size_t indexOffset, SerialDomain domain)
				{
					if (formatted <= indexOffset) return;
					const std::size_t wanted = data[pos + indexOffset];
					if (wanted == 0) return;
					std::size_t current = 1, begin = stringsStart;
					while (begin < stringsEnd && current < wanted)
					{
						while (begin < stringsEnd && data[begin] != 0) ++begin;
						++begin;
						++current;
					}
					if (current != wanted || begin >= stringsEnd) return;
					std::size_t finish = begin;
					while (finish < stringsEnd && data[finish] != 0) ++finish;
					const std::size_t length = finish - begin;
					if (length == 0) return;
					const std::string replaced = virtualSerial(domain,
						std::string_view{reinterpret_cast<const char*>(data + begin), length});
					if (replaced.size() != length) return;
					std::memcpy(data + begin, replaced.data(), length);
					++changed;
				};

				if (type == 1)
				{
					rewriteString(7, SerialDomain::SmbiosSystem);
					if (formatted >= 0x18)
					{
						std::array<std::uint8_t, 16> uuid = detail::guid_text_to_bytes(m_profile.hardware.systemUuid);
						if (major > 2 || (major == 2 && minor >= 6))
						{
							std::swap(uuid[0], uuid[3]);
							std::swap(uuid[1], uuid[2]);
							std::swap(uuid[4], uuid[5]);
							std::swap(uuid[6], uuid[7]);
						}
						std::memcpy(data + pos + 8, uuid.data(), uuid.size());
						++changed;
					}
				}
				else if (type == 2) rewriteString(7, SerialDomain::SmbiosBoard);
				else if (type == 3) rewriteString(7, SerialDomain::SmbiosChassis);
				else if (type == 127) break;
				pos = next;
			}
			return changed;
		}

	private:
		static constexpr std::uint8_t kAdapterGuidTag = 100;
		static constexpr std::uint8_t kMacTag = 101;
		static constexpr std::size_t kMaxAliases = 4096;

		std::uint64_t saltFor(SerialDomain domain) const
		{
			switch (domain)
			{
			case SerialDomain::Disk:
			case SerialDomain::PnpStorageInstance:
				return m_profile.storage.salt;
			case SerialDomain::PnpNetworkInstance:
				return m_profile.network.salt;
			default:
				return m_profile.hardware.salt;
			}
		}

		bool isVirtual(SerialDomain domain, const std::string& value) const
		{
			return isVirtualText(static_cast<std::uint8_t>(domain), value);
		}

		bool isVirtualText(std::uint8_t tag, const std::string& value) const
		{
			std::lock_guard lock(m_aliasMutex);
			return m_aliases.contains(std::string(1, static_cast<char>(tag)) + value);
		}

		void remember(SerialDomain domain, const std::string& value) const
		{
			rememberText(static_cast<std::uint8_t>(domain), value);
		}

		void rememberText(std::uint8_t tag, const std::string& value) const
		{
			std::lock_guard lock(m_aliasMutex);
			// Bounded: a process sees a handful of devices; losing the table only costs idempotence of old values.
			if (m_aliases.size() >= kMaxAliases) m_aliases.clear();
			m_aliases.insert(std::string(1, static_cast<char>(tag)) + value);
		}

		DeviceProfile m_profile;
		mutable std::mutex m_aliasMutex;
		mutable std::unordered_set<std::string> m_aliases;
	};
}
