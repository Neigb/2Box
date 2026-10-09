module;
#include "DeviceLaunch.hpp"
module Launcher;

import "sys_defs.h";
#ifndef _SYS_DEFS_H_
#pragma message("Just for IntelliSense. You should not see this message!")
import "sys_defs.hpp";
#endif

import std;
import MainApp;
import EssentialData;
import Utility.SystemInfo;
import Biz.Core;

namespace
{
	// Decide, for this one launch, which hooks the target gets and whether a device profile is active.
	// Default (no policy rule) is plain multi-instance isolation: no device
	// capability, no profile created, nothing device-related sent to the target.
	devid::LaunchConfig resolve_launch_config(const std::shared_ptr<biz::Env>& env, std::wstring_view exePath)
	{
		namespace fs = std::filesystem;
		const devid::InstanceIdentity instance = env->getInstanceIdentity();
		devid::LaunchConfig config;
		config.sessionId = instance.sessionId;
		config.objectNamespaceId = instance.objectNamespaceId;

		// Per-application policy, re-read on every launch. No policy file or no matching rule == plain multi-instance.
		std::uint32_t capabilities = devid::kCapNone;
		const fs::path policyPath{fs::path{app().exeDir()} / fs::path{L"Env\\data\\device-policy.ini"}};
		std::error_code ec;
		if (fs::exists(policyPath, ec))
		{
			std::ifstream file{policyPath, std::ios::binary};
			const std::string text{std::istreambuf_iterator<char>{file}, std::istreambuf_iterator<char>{}};
			const devid::DevicePolicy policy = devid::parse_policy(text);
			if (!policy.errors.empty())
			{
				throw std::runtime_error(std::format("device-policy.ini: {}", policy.errors.front()));
			}
			capabilities = policy.resolve(devid::detail::path_to_utf8(fs::path{exePath}));
		}
		config.capabilities = devid::normalize_capabilities(capabilities);

		if (config.deviceSimulationEnabled())
		{
			const devid::DeviceProfileStore store{biz::env_mgr().deviceProfileDirectory()};
			std::seed_seq seed{std::random_device{}(), std::random_device{}(), std::random_device{}(), std::random_device{}()};
			std::mt19937_64 rng{seed};
			// Created and bound exactly once per environment; later launches (and restarts) load the same file.
			config.profile = devid::obtain_profile(store, env->getDeviceProfileId(), [&] { return rng(); },
				[&](std::uint64_t profileId) { biz::env_mgr().bindDeviceProfile(env, profileId); });
		}
		return config;
	}

	PROCESS_INFORMATION create_and_inject(const biz::Env* env, std::wstring_view exePath, std::wstring_view params,
	                                      const devid::LaunchConfig& launchConfig)
	{
		PROCESS_INFORMATION procInfo = {nullptr};
		STARTUPINFOW startupInfo = {sizeof(startupInfo)};
		namespace fs = std::filesystem;
		const fs::path targetPath{exePath};
		std::wstring cmdLine = params.empty() ? std::format(L"\"{}\"", targetPath.native()) : std::format(L"\"{}\" {}", targetPath.native(), params);
		if (!DetourCreateProcessWithDllExW(targetPath.c_str(), cmdLine.data(), nullptr, nullptr, FALSE,
		                                   CREATE_DEFAULT_ERROR_MODE | CREATE_SUSPENDED, nullptr,
		                                   std::filesystem::path{exePath}.parent_path().native().c_str(), &startupInfo, &procInfo,
		                                   env->ensureDllInDeviceAndReturnPath().c_str(), &::CreateProcessW))
		{
			throw std::runtime_error(std::format("CreateProcessW Failed, error code: {}", GetLastError()));
		}
		try
		{
			const std::wstring_view rootPath = app().exeDir();
			const std::string launchConfigText = devid::encode_launch_config(launchConfig);
			const std::uint32_t rootPathCount = static_cast<std::uint32_t>(rootPath.length());
			const std::uint32_t rootPathSize = rootPathCount * sizeof(wchar_t);
			const std::uint32_t launchConfigSize = static_cast<std::uint32_t>(launchConfigText.size());
			const std::uint32_t paramsSize = FIELD_OFFSET(DetourInjectParams, rootPath) + rootPathSize + launchConfigSize;
			std::vector<std::byte> buffer(paramsSize);
			DetourInjectParams* injectParams = reinterpret_cast<DetourInjectParams*>(buffer.data());
			injectParams->version = biz::get_core_data().version;
			injectParams->envFlag = env->getFlag();
			injectParams->envIndex = env->getIndex();
			injectParams->rootPathCount = rootPathCount;
			injectParams->launchConfigBytes = launchConfigSize;
			memcpy(injectParams->rootPath, rootPath.data(), rootPathSize);
			memcpy(reinterpret_cast<std::byte*>(injectParams->rootPath) + rootPathSize, launchConfigText.data(), launchConfigSize);
			if (!DetourCopyPayloadToProcess(procInfo.hProcess, DETOUR_INJECT_PARAMS_GUID, injectParams, paramsSize))
			{
				throw std::runtime_error(std::format("copy payload failed, error code: {}", GetLastError()));
			}
		}
		catch (...)
		{
			TerminateProcess(procInfo.hProcess, 0);
			CloseHandle(procInfo.hThread);
			CloseHandle(procInfo.hProcess);
			throw;
		}
		return procInfo;
	}
}

namespace biz
{
	void Launcher::run(const std::shared_ptr<Env>& env, std::wstring_view exePath, std::wstring_view params /*= L""*/)
	{
		m_asyncScope.spawn(launch(env, exePath, params));
	}

	void Launcher::runInNewEnv(std::wstring_view exePath, std::wstring_view params /*= L""*/)
	{
		m_asyncScope.spawn(launch(std::shared_ptr<Env>{}, exePath, params));
	}

	coro::LazyTask<void> Launcher::coRun(std::shared_ptr<Env> env, std::wstring_view exePath, std::wstring_view params)
	{
		coro::SharedTask<void> sharedTask = coro::start_and_shared(launchInternal(env, std::wstring{exePath}, std::wstring{params}));
		m_asyncScope.spawn(sharedTask);
		co_await sharedTask;
		co_return;
	}

	coro::LazyTask<void> Launcher::launch(const std::shared_ptr<Env>& env, std::wstring_view exePath, std::wstring_view params) const
	{
		try
		{
			co_await launchInternal(env, std::wstring{exePath}, std::wstring{params});
		}
		catch (const std::exception& e)
		{
			show_utf8_error_message(std::format("启动进程失败：{}", e.what()));
		}
		catch (...)
		{
			show_error_message(L"启动进程失败：发生未知错误");
		}
		co_return;
	}

	coro::LazyTask<void> Launcher::launchInternal(std::shared_ptr<Env> env, std::wstring exePath, std::wstring params) const
	{
		co_await sched::transfer_to(m_execCtx);

		if (!env)
		{
			env = env_mgr().createEnv();
		}
		// Tell the environment a launch of this executable is under way (consumed when the process logs in).
		env->addPendingLaunch(exePath);
		// Resolve before creating the process: a damaged profile or policy file must fail the launch, not start a different machine.
		const devid::LaunchConfig launchConfig = resolve_launch_config(env, exePath);
		const PROCESS_INFORMATION procInfo = create_and_inject(env.get(), exePath, params, launchConfig);
		ResumeThread(procInfo.hThread);
		CloseHandle(procInfo.hThread);
		CloseHandle(procInfo.hProcess);
		co_return;
	}
}
