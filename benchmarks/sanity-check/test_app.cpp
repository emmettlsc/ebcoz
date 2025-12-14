/*
g++ test_app.cpp \
    -O2 \
    -g -gdwarf-4 \
    -fno-omit-frame-pointer \
    -Wl,--no-as-needed \
    -ldl \
    -pthread \
    -o test_app
 */
#include <iostream>
#include <thread>
#include <mutex>
#include <vector>
#include <chrono>
#include "../../src/profiler/include/coz.h"

std::mutex m;
long shared_counter = 0;

void worker(int id) {
    for (int i = 0; i < 1'000'000; i++) {

        // Intentional lock bottleneck
        {
            std::lock_guard<std::mutex> lk(m);
            shared_counter++;
        }

        // Do some "work"
        for (volatile int j = 0; j < 3000; j++) {
            // burn CPU
        }

        // Simulate blocking
        if (i % 50000 == 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }

        if ((i % 10000) == 0) {
            COZ_PROGRESS_NAMED("worker_iter");
        }
    }
}

int main() {
    std::cout << "Starting dummy workload...\n";

    const int N = 4;
    std::vector<std::thread> threads;
    threads.reserve(N);

    for (int i = 0; i < N; i++) {
        threads.emplace_back(worker, i);
        COZ_PROGRESS_NAMED("worker_start");
    }

    for (auto& t : threads) {
        t.join();
    }

    std::cout << "Done. Final counter = " << shared_counter << "\n";
    return 0;
}
