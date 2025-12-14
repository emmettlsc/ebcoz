package main

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// Busy-loop CPU for approx ms milliseconds.
func busyMs(ms int) {
	start := time.Now()
	for {
		if time.Since(start) >= time.Duration(ms)*time.Millisecond {
			return
		}
		// prevent compiler from optimizing away
		_ = atomic.AddUint64(new(uint64), 0)
	}
}

// Spin-based binary semaphore for decode, m = 1.
var decodeToken int32 = 1

func acquireDecodeTokenSpin(spinMs int) {
	start := time.Now()
	for {
		if atomic.CompareAndSwapInt32(&decodeToken, 1, 0) {
			// acquired
			return
		}
		// tight spin
		if spinMs > 0 && time.Since(start) >= time.Duration(spinMs)*time.Millisecond {
			// For synthetic gating, roughly bound spin.
			return
		}
	}
}

func releaseDecodeToken() {
	atomic.StoreInt32(&decodeToken, 1)
}

func branchU() {
	// Long RPC
	time.Sleep(140 * time.Millisecond)
	// Short decode
	busyMs(1)
}

func branchP() {
	// Short RPC
	time.Sleep(80 * time.Millisecond)
	// Gating spin then long decode
	acquireDecodeTokenSpin(8)
	busyMs(55)
	releaseDecodeToken()
}

func branchC() {
	// Medium RPC
	time.Sleep(110 * time.Millisecond)
	// Small overlapped spin + decode
	acquireDecodeTokenSpin(2)
	busyMs(15)
	releaseDecodeToken()
}

func main() {
	const numRequests = 500

	for i := 0; i < numRequests; i++ {
		var wg sync.WaitGroup
		wg.Add(3)

		go func() {
			defer wg.Done()
			branchU()
		}()
		go func() {
			defer wg.Done()
			branchP()
		}()
		go func() {
			defer wg.Done()
			branchC()
		}()

		wg.Wait()
		// This is the logical “request complete” point.
		// For LW/BCOZ/eBPF you will treat this as progress.
	}

	fmt.Println("All requests completed.")
}
