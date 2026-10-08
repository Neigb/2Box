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
	using WmiQueryAsync = HRESULT (STDMETHODCALLTYPE*)(IWbemServices*, const BSTR, const BSTR,
		long, IWbemContext*, IWbemObjectSink*);
	using WmiGetObjectAsync = HRESULT (STDMETHODCALLTYPE*)(IWbemServices*, const BSTR,
		long, IWbemContext*, IWbemObjectSink*);
	using WmiCreateEnumAsync = HRESULT (STDMETHODCALLTYPE*)(IWbemServices*, const BSTR,
		long, IWbemContext*, IWbemObjectSink*);
	using WmiSinkIndicate = HRESULT (STDMETHODCALLTYPE*)(IWbemObjectSink*, long, IWbemClassObject**);
	using WmiClassFactoryCreateInstance = HRESULT (STDMETHODCALLTYPE*)(IClassFactory*, IUnknown*, REFIID, void**);
	using WmiEnumNext = HRESULT (STDMETHODCALLTYPE*)(IEnumWbemClassObject*, long, ULONG,
		IWbemClassObject**, ULONG*);
	using WmiCallResultGet = HRESULT (STDMETHODCALLTYPE*)(IWbemCallResult*, long, IWbemClassObject**);
	using WmiGet = HRESULT (STDMETHODCALLTYPE*)(IWbemClassObject*, LPCWSTR, long, VARIANT*, CIMTYPE*, long*);
	using WmiNext = HRESULT (STDMETHODCALLTYPE*)(IWbemClassObject*, long, BSTR*, VARIANT*, CIMTYPE*, long*);

	std::mutex wmiMethodMutex;
	WmiConnect originalWmiConnect{};
	WmiQuery originalWmiQuery{};
	WmiGetObject originalWmiGetObject{};
	WmiCreateEnum originalWmiCreateEnum{};
	WmiQueryAsync originalWmiQueryAsync{};
	WmiGetObjectAsync originalWmiGetObjectAsync{};
	WmiCreateEnumAsync originalWmiCreateEnumAsync{};
	WmiSinkIndicate originalWmiSinkIndicate{};
	WmiClassFactoryCreateInstance originalWmiClassFactoryCreateInstance{};
	WmiEnumNext originalWmiEnumNext{};
	WmiCallResultGet originalWmiCallResultGet{};
	WmiGet originalWmiGet{};
	WmiNext originalWmiNext{};

	void watch_wmi_locator(IUnknown* unknown);

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
			static_cast<unsigned>(bytes[0]), delimiter, static_cast<unsigned>(bytes[1]), delimiter,
			static_cast<unsigned>(bytes[2]), delimiter, static_cast<unsigned>(bytes[3]), delimiter,
			static_cast<unsigned>(bytes[4]), delimiter, static_cast<unsigned>(bytes[5]));
	}

	// Each data domain is rewritten here only when the launch plan simulates it, and with the same
	// DeviceIdentityProvider functions the other APIs (DeviceIoControl, IP Helper, SMBIOS table) use,
	// so one device reports one identity everywhere. Processor identifiers are deliberately not touched:
	// CPUID cannot be hooked, so rewriting ProcessorId would make WMI contradict the CPU.
	std::optional<std::wstring> wmi_virtual_value(std::wstring_view className, std::wstring_view property,
		std::wstring_view source)
	{
		const global::Data& data = global::Data::get();
		const bool disk = data.storageSimulated()
			&& (wmi_equal(className, L"Win32_DiskDrive") || wmi_equal(className, L"Win32_PhysicalMedia"));
		const bool adapter = data.networkSimulated()
			&& (wmi_equal(className, L"Win32_NetworkAdapter") || wmi_equal(className, L"Win32_NetworkAdapterConfiguration"));
		const bool smbios = data.smbiosSimulated();
		if (!disk && !adapter && !smbios) return std::nullopt;
		if (adapter && wmi_equal(property, L"MACAddress")) return wmi_virtual_mac(source);
		const auto ascii = wmi_ascii(source);
		if (!ascii || ascii->empty()) return std::nullopt;
		const auto widen = [](const std::string& text) { return std::wstring{text.begin(), text.end()}; };
		if (smbios && wmi_equal(className, L"Win32_ComputerSystemProduct") && wmi_equal(property, L"UUID"))
		{
			const std::string value = data.virtualSystemUuid(*ascii);
			if (value == *ascii) return std::nullopt;
			return widen(value);
		}
		if (adapter && (wmi_equal(property, L"GUID") || wmi_equal(property, L"SettingID")))
		{
			const std::string value = data.virtualAdapterGuid(*ascii);
			if (value == *ascii) return std::nullopt;
			return widen(value);
		}
		if (disk && wmi_equal(property, L"SerialNumber"))
		{
			return widen(data.virtualDiskSerial(*ascii));
		}
		if (smbios)
		{
			if ((wmi_equal(className, L"Win32_BIOS") && wmi_equal(property, L"SerialNumber"))
				|| (wmi_equal(className, L"Win32_ComputerSystemProduct") && wmi_equal(property, L"IdentifyingNumber")))
				return widen(data.virtualSystemSerial(*ascii));
			if (wmi_equal(className, L"Win32_BaseBoard") && wmi_equal(property, L"SerialNumber"))
				return widen(data.virtualBoardSerial(*ascii));
			if (wmi_equal(className, L"Win32_SystemEnclosure") && wmi_equal(property, L"SerialNumber"))
				return widen(data.virtualChassisSerial(*ascii));
		}
		if ((disk || adapter) && wmi_equal(property, L"PNPDeviceID"))
		{
			const std::size_t slash = source.rfind(L'\\');
			if (slash == std::wstring_view::npos || slash + 1 == source.size()) return std::nullopt;
			const auto suffix = wmi_ascii(source.substr(slash + 1));
			if (!suffix) return std::nullopt;
			const std::string virtualSuffix = data.virtualPnpInstance(adapter, *suffix);
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

	HRESULT STDMETHODCALLTYPE wmi_sink_indicate(IWbemObjectSink* sink, long count,
		IWbemClassObject** objects)
	{
		const DWORD error = GetLastError();
		if (count > 0 && objects)
		{
			for (long i = 0; i < count; ++i) watch_wmi_object(objects[i]);
		}
		SetLastError(error);
		return originalWmiSinkIndicate(sink, count, objects);
	}

	void watch_wmi_sink(IWbemObjectSink* sink)
	{
		watch_wmi_method(sink, 3, originalWmiSinkIndicate, &wmi_sink_indicate);
	}

	HRESULT STDMETHODCALLTYPE wmi_class_factory_create_instance(IClassFactory* factory, IUnknown* outer,
		REFIID iid, void** result)
	{
		const HRESULT status = originalWmiClassFactoryCreateInstance(factory, outer, iid, result);
		const DWORD error = GetLastError();
		if (SUCCEEDED(status) && result && *result) watch_wmi_locator(static_cast<IUnknown*>(*result));
		SetLastError(error);
		return status;
	}

	void watch_wmi_class_factory(IClassFactory* factory)
	{
		watch_wmi_method(factory, 3, originalWmiClassFactoryCreateInstance, &wmi_class_factory_create_instance);
	}

	HRESULT STDMETHODCALLTYPE wmi_enum_next(IEnumWbemClassObject* enumeration, long timeout, ULONG count,
		IWbemClassObject** objects, ULONG* returned)
	{
		const HRESULT result = originalWmiEnumNext(enumeration, timeout, count, objects, returned);
		const DWORD error = GetLastError();
		if (SUCCEEDED(result) && objects && returned)
			for (ULONG i = 0; i < count && i < *returned; ++i) watch_wmi_object(objects[i]);
		SetLastError(error);
		return result;
	}

	void watch_wmi_enum(IEnumWbemClassObject* enumeration)
	{
		watch_wmi_method(enumeration, 4, originalWmiEnumNext, &wmi_enum_next);
	}

	HRESULT STDMETHODCALLTYPE wmi_call_result_get(IWbemCallResult* resultObject, long timeout,
		IWbemClassObject** object)
	{
		const HRESULT result = originalWmiCallResultGet(resultObject, timeout, object);
		const DWORD error = GetLastError();
		if (SUCCEEDED(result) && object) watch_wmi_object(*object);
		SetLastError(error);
		return result;
	}

	void watch_wmi_call_result(IWbemCallResult* result)
	{
		watch_wmi_method(result, 3, originalWmiCallResultGet, &wmi_call_result_get);
	}

	HRESULT STDMETHODCALLTYPE wmi_query_async(IWbemServices* service, const BSTR language,
		const BSTR query, long flags, IWbemContext* context, IWbemObjectSink* sink)
	{
		const DWORD error = GetLastError();
		watch_wmi_sink(sink);
		SetLastError(error);
		return originalWmiQueryAsync(service, language, query, flags, context, sink);
	}

	HRESULT STDMETHODCALLTYPE wmi_get_object_async(IWbemServices* service, const BSTR path,
		long flags, IWbemContext* context, IWbemObjectSink* sink)
	{
		const DWORD error = GetLastError();
		watch_wmi_sink(sink);
		SetLastError(error);
		return originalWmiGetObjectAsync(service, path, flags, context, sink);
	}

	HRESULT STDMETHODCALLTYPE wmi_create_enum_async(IWbemServices* service, const BSTR filter,
		long flags, IWbemContext* context, IWbemObjectSink* sink)
	{
		const DWORD error = GetLastError();
		watch_wmi_sink(sink);
		SetLastError(error);
		return originalWmiCreateEnumAsync(service, filter, flags, context, sink);
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
		if (SUCCEEDED(result) && callResult) watch_wmi_call_result(*callResult);
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
		watch_wmi_method(service, 7, originalWmiGetObjectAsync, &wmi_get_object_async);
		watch_wmi_method(service, 18, originalWmiCreateEnum, &wmi_create_enum);
		watch_wmi_method(service, 19, originalWmiCreateEnumAsync, &wmi_create_enum_async);
		watch_wmi_method(service, 20, originalWmiQuery, &wmi_query);
		watch_wmi_method(service, 21, originalWmiQueryAsync, &wmi_query_async);
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
	HRESULT STDAPICALLTYPE CoGetClassObject(REFCLSID clsid, DWORD context, COSERVERINFO* reserved,
		REFIID iid, LPVOID* result)
	{
		const HRESULT status = Trampoline(clsid, context, reserved, iid, result);
		const DWORD error = GetLastError();
		if (SUCCEEDED(status) && result && *result && is_wmi_locator(clsid) && IsEqualIID(iid, IID_IClassFactory))
			watch_wmi_class_factory(static_cast<IClassFactory*>(*result));
		SetLastError(error);
		return status;
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
		create_hook_by_func_ptr<&::CoGetClassObject>().setHookFromGetter([](auto trampoline)
		{
			return HookInfo{&CoGetClassObject<trampoline.value>};
		});
	}
}
