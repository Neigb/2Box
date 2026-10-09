#pragma once

// Plain C++ (no Windows or RPC types) so the caching logic can be unit tested anywhere.

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <unordered_set>

// A short-lived local copy of "what exists in the other environments".
//
// Window and process hooks sit on very hot paths (GetWindow walks, OpenProcess, process listings, message loops).
// Asking the host about every single handle meant thousands of synchronous RPCs per second per process, which
// starved the host and stalled the callers' message threads. One RPC now fetches the whole set; every query inside
// the TTL is a local lookup. Staleness is bounded by the TTL: a window or process of another environment becomes
// hidden at most one TTL after it appears.
class OtherEnvSnapshot
{
public:
	using IdSet = std::unordered_set<std::uint64_t>;
	using Fetch = std::optional<IdSet> (*)(unsigned long long envFlag);

	OtherEnvSnapshot(Fetch fetch, std::chrono::milliseconds ttl) : m_fetch(fetch), m_ttl(ttl)
	{
	}

	// Never null once a first fetch succeeded. Before that (host unreachable) returns null and callers treat
	// everything as "other environment", the same fail-closed answer a failed per-handle RPC used to give.
	std::shared_ptr<const IdSet> get(unsigned long long envFlag)
	{
		const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
		if (now >= m_nextRefresh.load(std::memory_order_acquire))
		{
			refresh(envFlag, now);
		}
		std::lock_guard lock(m_mutex);
		return m_set;
	}

	bool contains(unsigned long long envFlag, std::uint64_t id)
	{
		const std::shared_ptr<const IdSet> set = get(envFlag);
		return !set || set->contains(id);
	}

private:
	void refresh(unsigned long long envFlag, std::chrono::steady_clock::rep now)
	{
		std::unique_lock refreshLock(m_refreshMutex, std::try_to_lock);
		if (!refreshLock)
		{
			// Someone else is fetching. Wait only when there is nothing to answer with yet.
			if (!m_initialized.load(std::memory_order_acquire))
			{
				refreshLock.lock();
			}
			else
			{
				return;
			}
		}
		if (m_nextRefresh.load(std::memory_order_acquire) > now && m_initialized.load(std::memory_order_acquire))
		{
			return; // refreshed while we waited for the lock
		}
		std::optional<IdSet> fresh;
		try
		{
			fresh = m_fetch(envFlag);
		}
		catch (...)
		{
		}
		// Publish first, then move the deadline: a thread that sees the new deadline must also see the new set.
		if (fresh)
		{
			auto snapshot = std::make_shared<const IdSet>(std::move(*fresh));
			std::lock_guard lock(m_mutex);
			m_set = std::move(snapshot);
			m_initialized.store(true, std::memory_order_release);
		}
		// A failed fetch keeps the previous snapshot and is retried after one TTL (no retry storm).
		const auto ttl = std::chrono::duration_cast<std::chrono::steady_clock::duration>(m_ttl).count();
		m_nextRefresh.store(std::chrono::steady_clock::now().time_since_epoch().count() + ttl, std::memory_order_release);
	}

	Fetch m_fetch;
	std::chrono::milliseconds m_ttl;
	std::atomic<std::chrono::steady_clock::rep> m_nextRefresh{0};
	std::atomic<bool> m_initialized{false};
	std::mutex m_refreshMutex;
	std::mutex m_mutex;
	std::shared_ptr<const IdSet> m_set;
};
