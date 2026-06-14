package run

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// readCgroupOrHostMemBytes returns the memory ceiling that paqet
// should plan against, in bytes. Preference order:
//  1. cgroup v2 memory.max (typical on systemd hosts and containers)
//  2. cgroup v1 memory.limit_in_bytes (older containers, k8s)
//  3. /proc/meminfo MemTotal (bare metal / no cgroup limit)
//
// Returns 0 if none can be read. Returns 0 if the cgroup value is
// "max" (unlimited) — falls through to host total in that case.
//
// Why prefer cgroup over MemTotal: paqet usually runs under systemd
// or in a container, which sets a memory ceiling well below host
// total. Targeting host RAM would let paqet OOM the rest of the box.
func readCgroupOrHostMemBytes() int64 {
	// cgroup v2
	if b, ok := readCgroupV2Limit(); ok {
		return b
	}
	// cgroup v1
	if b, ok := readCgroupV1Limit(); ok {
		return b
	}
	// host total
	return readMemTotal()
}

func readCgroupV2Limit() (int64, bool) {
	data, err := os.ReadFile("/sys/fs/cgroup/memory.max")
	if err != nil {
		return 0, false
	}
	s := strings.TrimSpace(string(data))
	if s == "max" || s == "" {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		return 0, false
	}
	return n, true
}

func readCgroupV1Limit() (int64, bool) {
	data, err := os.ReadFile("/sys/fs/cgroup/memory/memory.limit_in_bytes")
	if err != nil {
		return 0, false
	}
	s := strings.TrimSpace(string(data))
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		return 0, false
	}
	// cgroup v1 reports an absurdly large sentinel when "unlimited"
	// (typically 9_223_372_036_854_771_712). Cap at 1 TB as a sanity
	// check; anything beyond that we treat as "unlimited" and fall
	// through.
	const sanityCap = int64(1) << 40 // 1 TB
	if n >= sanityCap {
		return 0, false
	}
	return n, true
}

func readMemTotal() int64 {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "MemTotal:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0
		}
		kb, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			return 0
		}
		return kb * 1024
	}
	return 0
}
