namespace hook
{
	using WmiConnect = HRESULT (STDMETHODCALLTYPE*)(IWbemLocator*, const BSTR, const BSTR, const BSTR,
		const BSTR, long, const BSTR, IWbemContext*, IWbemServices**);
	using WmiQuery = HRESULT (STDMETHODCALLTYPE*)(IWbemServices*, const BSTR, const BSTR, long,
		IWbemContext*, IEnumWbemClassObject**);
	using WmiGetObject = HRESULT (STDMETHODCALLTYPE*)(IWbemServices*, const BSTR, long,
		IWbemContext*, IWbemClassObject**, IWbemCallResult**);
	using WmiCreateEnum = HRESULT (STDMETHODCALLTYPE*)(IWbemServices*, const BSTR, long,
		IWbemContext*, IEnumWbemClassObject**);
	using WmiEnumNext = HRESULT (STDMETHODCALLTYPE*)(IEnumWbemClassObject*, long, ULONG,
		IWbemClassObject**, ULONG*);
	using WmiGet = HRESULT (STDMETHODCALLTYPE*)(IWbemClassObject*, LPCWSTR, long, VARIANT*, CIMTYPE*, long*);
	using WmiNext = HRESULT (STDMETHODCALLTYPE*)(IWbemClassObject*, long, BSTR*, VARIANT*, CIMTYPE*, long*);

	std::mutex wmiMethodMutex;
	WmiConnect originalWmiConnect{};
	WmiQuery originalWmiQuery{};
	WmiGetObject originalWmiGetObject{};
	WmiCreateEnum originalWmiCreateEnum{};
	WmiEnumNext originalWmiEnumNext{};
	WmiGet originalWmiGet{};
	WmiNext originalWmiNext{};

	template <typename Function>
	void watch_wmi_method(void* instance, std::size_t slot, Function& trampoline, Function replacement)
	{
		if (!instance) return;
		std::lock_guard lock(wmiMethodMutex);
		if (trampoline) return;
		trampoline = reinterpret_cast<Function>((*static_cast<void***>(instance))[slot]);
		if (!trampoline || DetourTransactionBegin() != NO_ERROR)
		{
			trampoline = nullptr;
			return;
		}
		DetourUpdateThread(GetCurrentThread());
		if (DetourAttach(reinterpret_cast<void**>(&trampoline), reinterpret_cast<void*>(replacement)) != NO_ERROR)
		{
			DetourTransactionAbort();
			trampoline = nullptr;
			return;
		}
		if (DetourTransactionCommit() != NO_ERROR) trampoline = nullptr;
	}

	bool wmi_equal(std::wstring_view a, std::wstring_view b)
	{
		return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin(),
			[](wchar_t x, wchar_t y) { return std::towlower(x) == std::towlower(y); });
	}

	std::optional<std::string> wmi_ascii(std::wstring_view source)
	{
		std::string result;
		result.reserve(source.size());
		for (wchar_t c : source)
		{
			if (c > 127) return std::nullopt;
			result.push_back(static_cast<char>(c));
		}
		return result;
	}

	std::optional<std::wstring> wmi_virtual_mac(std::wstring_view source)
	{
		if (source.size() != 17) return std::nullopt;
		const wchar_t delimiter = source[2];
		if (delimiter != L':' && delimiter != L'-') return std::nullopt;
		const auto digit = [](wchar_t c) -> int
		{
			if (c >= L'0' && c <= L'9') return c - L'0';
			if (c >= L'A' && c <= L'F') return c - L'A' + 10;
			if (c >= L'a' && c <= L'f') return c - L'a' + 10;
			return -1;
		};
		std::array<std::uint8_t, 6> bytes{};
		for (std::size_t i = 0; i < bytes.size(); ++i)
		{
			const int hi = digit(source[i * 3]);
			const int lo = digit(source[i * 3 + 1]);
			if (hi < 0 || lo < 0 || (i < 5 && source[i * 3 + 2] != delimiter)) return std::nullopt;
			bytes[i] = static_cast<std::uint8_t>((hi << 4) | lo);
		}
		global::Data::get().virtualMac(bytes.data(), bytes.size());
		return std::format(L"{:02X}{}{:02X}{}{:02X}{}{:02X}{}{:02X}{}{:02X}",
			bytes[0], delimiter, bytes[1], delimiter, bytes[2], delimiter,
			bytes[3], delimiter, bytes[4], delimiter, bytes[5]);
	}

	std::optional<std::wstring> wmi_virtual_value(std::wstring_view className, std::wstring_view property,
		std::wstring_view source)
	{
		const bool disk = wmi_equal(className, L"Win32_DiskDrive") || wmi_equal(className, L"Win32_PhysicalMedia");
		const bool platform = wmi_equal(className, L"Win32_BIOS") || wmi_equal(className, L"Win32_BaseBoard")
			|| wmi_equal(className, L"Win32_ComputerSystemProduct") || wmi_equal(className, L"Win32_Processor");
		const bool adapter = wmi_equal(className, L"Win32_NetworkAdapter");
		if (adapter && wmi_equal(property, L"MACAddress")) return wmi_virtual_mac(source);
		const auto ascii = wmi_ascii(source);
		if (!ascii || ascii->empty()) return std::nullopt;
		if ((disk || platform) && (wmi_equal(property, L"SerialNumber")
			|| wmi_equal(property, L"IdentifyingNumber") || wmi_equal(property, L"ProcessorId")))
		{
			const std::string serial = global::Data::get().virtualDiskSerial(*ascii);
			return std::wstring{serial.begin(), serial.end()};
		}
		if (wmi_equal(className, L"Win32_ComputerSystemProduct") && wmi_equal(property, L"UUID"))
		{
			const std::string a = global::Data::get().virtualDiskSerial(*ascii);
			const std::string b = global::Data::get().virtualDiskSerial(*ascii + "UUID");
			if (a.size() != 16 || b.size() != 16) return std::nullopt;
			std::wstring hex{a.begin(), a.end()};
			hex.append(b.begin(), b.end());
			hex[12] = L'4';
			hex[16] = L'8';
			return std::format(L"{}-{}-{}-{}-{}", hex.substr(0, 8), hex.substr(8, 4),
				hex.substr(12, 4), hex.substr(16, 4), hex.substr(20));
		}
		if ((disk || adapter) && wmi_equal(property, L"PNPDeviceID"))
		{
			const std::size_t slash = source.rfind(L'\\');
			if (slash == std::wstring_view::npos || slash + 1 == source.size()) return std::nullopt;
			const auto suffix = wmi_ascii(source.substr(slash + 1));
			if (!suffix) return std::nullopt;
			const std::string virtualSuffix = global::Data::get().virtualDiskSerial(*suffix);
			std::wstring result{source.substr(0, slash + 1)};
			result.append(virtualSuffix.begin(), virtualSuffix.end());
			return result;
		}
		return std::nullopt;
	}

	void rewrite_wmi_property(IWbemClassObject* object, LPCWSTR property, VARIANT* value)
	{
		if (!object || !property || !value || value->vt != VT_BSTR || !value->bstrVal
			|| wmi_equal(property, L"__CLASS") || !originalWmiGet) return;
		VARIANT classValue;
		VariantInit(&classValue);
		if (FAILED(originalWmiGet(object, L"__CLASS", 0, &classValue, nullptr, nullptr))) return;
		if (classValue.vt == VT_BSTR && classValue.bstrVal)
		{
			try
			{
				const auto replacement = wmi_virtual_value(
					std::wstring_view{classValue.bstrVal, SysStringLen(classValue.bstrVal)}, property,
					std::wstring_view{value->bstrVal, SysStringLen(value->bstrVal)});
				if (replacement)
				{
					BSTR text = SysAllocStringLen(replacement->data(), static_cast<UINT>(replacement->size()));
					if (text)
					{
						SysFreeString(value->bstrVal);
						value->bstrVal = text;
					}
				}
			}
			catch (...) {}
		}
		VariantClear(&classValue);
	}

	HRESULT STDMETHODCALLTYPE wmi_get(IWbemClassObject* object, LPCWSTR name, long flags,
		VARIANT* value, CIMTYPE* type, long* flavor)
	{
		const HRESULT result = originalWmiGet(object, name, flags, value, type, flavor);
		const DWORD error = GetLastError();
		if (SUCCEEDED(result)) rewrite_wmi_property(object, name, value);
		SetLastError(error);
		return result;
	}

	HRESULT STDMETHODCALLTYPE wmi_next(IWbemClassObject* object, long flags, BSTR* name,
		VARIANT* value, CIMTYPE* type, long* flavor)
	{
		const HRESULT result = originalWmiNext(object, flags, name, value, type, flavor);
		const DWORD error = GetLastError();
		if (SUCCEEDED(result) && name) rewrite_wmi_property(object, *name, value);
		SetLastError(error);
		return result;
	}

	void watch_wmi_object(IWbemClassObject* object)
	{
		watch_wmi_method(object, 4, originalWmiGet, &wmi_get);
		watch_wmi_method(object, 9, originalWmiNext, &wmi_next);
	}

	HRESULT STDMETHODCALLTYPE wmi_enum_next(IEnumWbemClassObject* enumeration, long timeout, ULONG count,
		IWbemClassObject** objects, ULONG* returned)
	{
		const HRESULT result = originalWmiEnumNext(enumeration, timeout, count, objects, returned);
		const DWORD error = GetLastError();
		if (SUCCEEDED(result) && objects && returned)
			for (ULONG i = 0; i < std::min(count, *returned); ++i) watch_wmi_object(objects[i]);
		SetLastError(error);
		return result;
	}

	void watch_wmi_enum(IEnumWbemClassObject* enumeration)
	{
		watch_wmi_method(enumeration, 4, originalWmiEnumNext, &wmi_enum_next);
	}

	HRESULT STDMETHODCALLTYPE wmi_query(IWbemServices* service, const BSTR language, const BSTR query,
		long flags, IWbemContext* context, IEnumWbemClassObject** enumeration)
	{
		const HRESULT result = originalWmiQuery(service, language, query, flags, context, enumeration);
		const DWORD error = GetLastError();
		if (SUCCEEDED(result) && enumeration) watch_wmi_enum(*enumeration);
		SetLastError(error);
		return result;
	}

	HRESULT STDMETHODCALLTYPE wmi_get_object(IWbemServices* service, const BSTR path, long flags,
		IWbemContext* context, IWbemClassObject** object, IWbemCallResult** callResult)
	{
		const HRESULT result = originalWmiGetObject(service, path, flags, context, object, callResult);
		const DWORD error = GetLastError();
		if (SUCCEEDED(result) && object) watch_wmi_object(*object);
		SetLastError(error);
		return result;
	}

	HRESULT STDMETHODCALLTYPE wmi_create_enum(IWbemServices* service, const BSTR filter, long flags,
		IWbemContext* context, IEnumWbemClassObject** enumeration)
	{
		const HRESULT result = originalWmiCreateEnum(service, filter, flags, context, enumeration);
		const DWORD error = GetLastError();
		if (SUCCEEDED(result) && enumeration) watch_wmi_enum(*enumeration);
		SetLastError(error);
		return result;
	}

	void watch_wmi_service(IWbemServices* service)
	{
		watch_wmi_method(service, 6, originalWmiGetObject, &wmi_get_object);
		watch_wmi_method(service, 18, originalWmiCreateEnum, &wmi_create_enum);
		watch_wmi_method(service, 20, originalWmiQuery, &wmi_query);
	}

	HRESULT STDMETHODCALLTYPE wmi_connect(IWbemLocator* locator, const BSTR resource, const BSTR user,
		const BSTR password, const BSTR locale, long flags, const BSTR authority,
		IWbemContext* context, IWbemServices** service)
	{
		const HRESULT result = originalWmiConnect(locator, resource, user, password, locale, flags, authority, context, service);
		const DWORD error = GetLastError();
		if (SUCCEEDED(result) && service) watch_wmi_service(*service);
		SetLastError(error);
		return result;
	}

	void watch_wmi_locator(IUnknown* unknown)
	{
		if (!unknown) return;
		IWbemLocator* locator = nullptr;
		if (SUCCEEDED(unknown->QueryInterface(IID_IWbemLocator, reinterpret_cast<void**>(&locator))))
		{
			watch_wmi_method(locator, 3, originalWmiConnect, &wmi_connect);
			locator->Release();
		}
	}

	bool is_wmi_locator(REFCLSID clsid)
	{
		return IsEqualCLSID(clsid, CLSID_WbemLocator) || IsEqualCLSID(clsid, CLSID_WbemAdministrativeLocator);
	}

	template <auto Trampoline>
	HRESULT STDAPICALLTYPE CoCreateInstance(REFCLSID clsid, LPUNKNOWN outer, DWORD context, REFIID iid, LPVOID* result)
	{
		const HRESULT status = Trampoline(clsid, outer, context, iid, result);
		const DWORD error = GetLastError();
		if (SUCCEEDED(status) && result && is_wmi_locator(clsid)) watch_wmi_locator(static_cast<IUnknown*>(*result));
		SetLastError(error);
		return status;
	}

	template <auto Trampoline>
	HRESULT STDAPICALLTYPE CoCreateInstanceEx(REFCLSID clsid, IUnknown* outer, DWORD context,
		COSERVERINFO* server, DWORD count, MULTI_QI* results)
	{
		const HRESULT status = Trampoline(clsid, outer, context, server, count, results);
		const DWORD error = GetLastError();
		if (SUCCEEDED(status) && results && is_wmi_locator(clsid))
			for (DWORD i = 0; i < count; ++i)
				if (SUCCEEDED(results[i].hr)) watch_wmi_locator(results[i].pItf);
		SetLastError(error);
		return status;
	}

	void hook_ole32()
	{
		create_hook_by_func_ptr<&::CoCreateInstance>().setHookFromGetter([](auto trampoline)
		{
			return HookInfo{&CoCreateInstance<trampoline.value>};
		});
		create_hook_by_func_ptr<&::CoCreateInstanceEx>().setHookFromGetter([](auto trampoline)
		{
			return HookInfo{&CoCreateInstanceEx<trampoline.value>};
		});
	}
}
