// Tests for the "other environments" snapshot cache used by the window/process hooks.
#include <atomic>
#include <cstdio>
#include <thread>
#include <vector>

#include "OtherEnvSnapshot.hpp"

namespace
{
	int failures = 0;
	int checks = 0;
#define CHECK(expr) do { ++checks; if (!(expr)) { ++failures; std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr); } } while (0)

	std::atomic<int> fetchCount{0};
	std::atomic<bool> fetchFails{false};
	std::atomic<std::uint64_t> generation{1};

	std::optional<OtherEnvSnapshot::IdSet> fetch(unsigned long long)
	{
		++fetchCount;
		if (fetchFails) throw 1;
		if (fetchFails.load()) return std::nullopt;
		return OtherEnvSnapshot::IdSet{generation.load(), 100, 200};
	}

	std::optional<OtherEnvSnapshot::IdSet> fetchNothing(unsigned long long)
	{
		++fetchCount;
		return std::nullopt;
	}
}

int main()
{
	using namespace std::chrono_literals;

	{
		// Many lookups inside the TTL cost exactly one fetch.
		fetchCount = 0; fetchFails = false; generation = 1;
		OtherEnvSnapshot snapshot{&fetch, 10s};
		for (int i = 0; i < 100000; ++i) CHECK(snapshot.contains(7, 100));
		CHECK(!snapshot.contains(7, 999));
		CHECK(fetchCount == 1);
	}
	{
		// After the TTL the set is refreshed.
		fetchCount = 0; generation = 1;
		OtherEnvSnapshot snapshot{&fetch, 20ms};
		CHECK(snapshot.contains(7, 1));
		CHECK(!snapshot.contains(7, 2));
		generation = 2;
		std::this_thread::sleep_for(60ms);
		CHECK(snapshot.contains(7, 2));
		CHECK(!snapshot.contains(7, 1));
		CHECK(fetchCount == 2);
	}
	{
		// A failing fetch keeps the previous snapshot and does not retry on every call.
		fetchCount = 0; fetchFails = false; generation = 1;
		OtherEnvSnapshot snapshot{&fetch, 20ms};
		CHECK(snapshot.contains(7, 100));
		fetchFails = true;
		std::this_thread::sleep_for(60ms);
		for (int i = 0; i < 1000; ++i) CHECK(snapshot.contains(7, 100) && !snapshot.contains(7, 5));
		CHECK(fetchCount <= 3);
	}
	{
		// Before any successful fetch everything counts as "other environment" (fail closed), without a retry storm.
		fetchCount = 0;
		OtherEnvSnapshot snapshot{&fetchNothing, 10s};
		CHECK(snapshot.get(7) == nullptr);
		for (int i = 0; i < 1000; ++i) CHECK(snapshot.contains(7, 12345));
		CHECK(fetchCount == 1);
	}
	{
		// Concurrent first use: one fetch, every thread gets an answer.
		fetchCount = 0; fetchFails = false; generation = 1;
		OtherEnvSnapshot snapshot{&fetch, 10s};
		std::atomic<int> wrong{0};
		std::vector<std::thread> threads;
		for (int t = 0; t < 8; ++t)
		{
			threads.emplace_back([&]
			{
				for (int i = 0; i < 20000; ++i)
				{
					if (!snapshot.contains(7, 200) || snapshot.contains(7, 31337)) ++wrong;
				}
			});
		}
		for (auto& thread : threads) thread.join();
		CHECK(wrong == 0);
		CHECK(fetchCount == 1);
	}
	std::printf("%d checks, %d failures\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
