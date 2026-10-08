#include "biz_initializer.h"
#include "probe_trace.h"

#include "DeviceLaunch.hpp"
#include "InstanceIdentity.hpp"

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

void initialize_global_data(const DetourInjectParams& params)
{
	const std::string_view launchConfigText{
		reinterpret_cast<const char*>(params.rootPath + params.rootPathCount), params.launchConfigBytes};
	devid::LaunchConfig launchConfig;
	// Payloads without a launch config (nothing asks for device simulation) mean the plain multi-instance default.
	launchConfig.objectNamespaceId = params.envFlag;
	if (!launchConfigText.empty())
	{
		devid::LaunchDecodeResult decoded = devid::decode_launch_config(launchConfigText);
		if (!decoded.config)
		{
			throw std::runtime_error(std::format("invalid launch config: {}", decoded.error));
		}
		launchConfig = std::move(*decoded.config);
	}
	const devid::InstanceIdentity instance{params.envFlag, params.envIndex, launchConfig.sessionId, launchConfig.objectNamespaceId};
	global::Data::get().initialize(params.version, instance, std::wstring_view{params.rootPath, params.rootPathCount},
		std::move(launchConfig), std::string{launchConfigText});
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
	const devid::HookPlan& plan = global::Data::get().hookPlan();
	probe_trace(plan.isolation ? "hook plan isolation" : "hook plan without isolation");
	if (global::Data::get().storageSimulated()) probe_trace("device storage simulated");
	if (global::Data::get().networkSimulated()) probe_trace("device network simulated");
	if (global::Data::get().smbiosSimulated()) probe_trace("device smbios simulated");
	if (global::Data::get().osSimulated()) probe_trace("device os simulated");
	hook::hook_all();
}

void biz_initialize(const DetourInjectParams* params)
{
	try
	{
		probe_trace("global data begin");
		initialize_global_data(*params);
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
