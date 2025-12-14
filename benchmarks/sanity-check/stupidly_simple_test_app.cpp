#include <iostream>
#include <thread>
#include <chrono>

void ez_stuff() {
    // work
    long sum = 0;
    for (int i = 0; i < 10'000'000; i++) {
        sum += i;
    }
    // one single context switch
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    std::cout << "Thread done, sum = " << sum << "\n";
}

int main() {
    std::cout << "Starting stupidly simple test...\n";
    std::thread t1(ez_stuff);
    std::thread t2(ez_stuff);
    t1.join();
    t2.join();
    return 0;
}
