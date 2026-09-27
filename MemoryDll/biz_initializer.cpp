#include "biz_initializer.h"
#include "probe_trace.h"

import std;
import GlobalData;
import RpcClient;
import Hook;

int filter_offline_error(unsigned int code)
{
	if (RpcExceptionFilter(code) == EXCEPTION_CONTINUE_SEARCH)
	{
		return EXCEPTION_CONTINUE_SEARCH;
	}
	if (code == 0xE06D7363)
	{
		return EXCEPTION_CONTINUE_SEARCH;
	}
	return EXCEPTION_EXECUTE_HANDLER;
}

HANDLE login_two_box()
{
	__try
	{
		const rpc::ClientDefault c;
		unsigned long long boxHandle = c.loginHost(GetCurrentProcessId(), global::Data::get().envFlag());
		return reinterpret_cast<HANDLE>(boxHandle);
	}
	__except (filter_offline_error(RpcExceptionCode()))
	{
		return nullptr;
	}
}

void request_window_inspection()
{
	__try
	{
		const rpc::ClientDefault c;
		c.requestWindowInspection(GetCurrentProcessId(), global::Data::get().envFlag());
	}
	__except (filter_offline_error(RpcExceptionCode()))
	{
	}
}

void initialize_global_data(SystemVersionInfo versionInfo, unsigned long long envFlag, unsigned long envIndex, std::wstring_view rootPath)
{
	global::Data::get().initialize(versionInfo, envFlag, envIndex, rootPath);
}

// 主程序退出后，受管理进程也会结束，避免进程间隔离状态不一致。
#define ALLOW_HOST_EXIT 0

void initialize_rpc()
{
	struct BoxSimpleWatcher
	{
		HANDLE quitEvent;
		std::thread thread;

		explicit BoxSimpleWatcher(HANDLE boxHandle)
		{
#if !ALLOW_HOST_EXIT
			if (boxHandle == nullptr)
			{
				TerminateProcess(GetCurrentProcess(), 1);
			}
#endif
			quitEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
			if (!quitEvent)
			{
				throw std::runtime_error(std::format("CreateEvent failed: {}", GetLastError()));
			}
			thread = std::thread([this, boxHandle]
			{
				watchLoop(boxHandle);
			});
		}

		~BoxSimpleWatcher()
		{
			if (thread.joinable())
			{
				if (SetEvent(quitEvent))
				{
					thread.join();
				}
				else
				{
					thread.detach();
				}
			}
			CloseHandle(quitEvent);
		}

		void watchLoop(HANDLE boxHandle) const
		{
			while (true)
			{
				if (!boxHandle)
				{
					try
					{
						boxHandle = login_two_box();
						if (boxHandle)
						{
							request_window_inspection();
						}
					}
					catch (...)
					{
						TerminateProcess(GetCurrentProcess(), 1);
					}
				}
				if (boxHandle)
				{
					std::vector handles{quitEvent, boxHandle};
					DWORD index = WaitForMultipleObjects(static_cast<DWORD>(handles.size()), handles.data(), FALSE, INFINITE);
					if (index >= handles.size())
					{
						TerminateProcess(GetCurrentProcess(), 1);
					}
					if (handles[index] == quitEvent)
					{
						break;
					}
					CloseHandle(boxHandle);
					boxHandle = nullptr;
				}
#if !ALLOW_HOST_EXIT
				TerminateProcess(GetCurrentProcess(), 1);
#endif
				std::this_thread::sleep_for(std::chrono::seconds(1));
			}
		}
	};

	static BoxSimpleWatcher watcher{login_two_box()};
}

void initialize_hook()
{
	wchar_t scope[16]{};
	const DWORD length = GetEnvironmentVariableW(L"WORKSPACE_HOOK_SCOPE", scope, static_cast<DWORD>(std::size(scope)));
	probe_trace(length == 6 && std::wstring_view{scope, length} == L"device" ? "hook scope device" :
		length == 7 && std::wstring_view{scope, length} == L"process" ? "hook scope process" : "hook scope full");
	hook::hook_all();
}

void biz_initialize(SystemVersionInfo versionInfo, unsigned long long envFlag, unsigned long envIndex, const wchar_t* rootPath, DWORD rootPathCount)
{
	try
	{
		probe_trace("global data begin");
		initialize_global_data(versionInfo, envFlag, envIndex, std::wstring_view{rootPath, rootPathCount});
		probe_trace("rpc begin");
		initialize_rpc();
		probe_trace("hooks begin");
		initialize_hook();
		probe_trace("hooks complete");
	}
	catch (const std::exception& error)
	{
		probe_trace("initialization exception");
		probe_trace(error.what());
		OutputDebugStringA(error.what());
		TerminateProcess(GetCurrentProcess(), 1);
	}
	catch (...)
	{
		probe_trace("initialization unknown exception");
		TerminateProcess(GetCurrentProcess(), 1);
	}
}
