package main

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"syscall"
)

type ProcessType int

const (
	ProcessTypeUnknown ProcessType = iota
	ProcessTypeSystemService
	ProcessTypeUserService
	ProcessTypeUserApp
	ProcessTypeScope
)

type ProcessInfo struct {
	Type        ProcessType
	ServiceName string
	CgroupPath  string
	IsSystem    bool
}

func getProcessSystemdInfo(pid int32) (*ProcessInfo, error) {
	cgroupData, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return nil, err
	}

	info := &ProcessInfo{
		Type: ProcessTypeUnknown,
	}

	// Find the systemd cgroup line
	lines := strings.Split(string(cgroupData), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, "::", 2)
		if len(parts) != 2 {
			continue
		}

		cgroupPath := parts[1]
		info.CgroupPath = cgroupPath

		// Analyze the cgroup path
		switch {
		case strings.HasPrefix(cgroupPath, "/system.slice/"):
			info.IsSystem = true
			if strings.HasSuffix(cgroupPath, ".service") {
				info.Type = ProcessTypeSystemService
				if match := regexp.MustCompile(`/([^/]+\.service)$`).FindStringSubmatch(cgroupPath); match != nil {
					info.ServiceName = match[1]
				}
			}

		case strings.Contains(cgroupPath, "/user.slice/"):
			info.IsSystem = false

			if strings.Contains(cgroupPath, "/app.slice/") {
				info.Type = ProcessTypeUserApp
				// Extract app name
				if match := regexp.MustCompile(`/app-([^/]+)\.scope$`).FindStringSubmatch(cgroupPath); match != nil {
					info.ServiceName = match[1]
				}
			} else if strings.Contains(cgroupPath, ".service") && !strings.Contains(cgroupPath, "user@") {
				info.Type = ProcessTypeUserService
			}

		case strings.HasSuffix(cgroupPath, ".scope"):
			info.Type = ProcessTypeScope
		}

		break // We found the systemd line
	}

	return info, nil
}

func getUcred(conn net.Conn) (*syscall.Ucred, error) {
	raw, err := conn.(*net.UnixConn).SyscallConn()
	if err != nil {
		return nil, err
	}

	var cred *syscall.Ucred
	err = raw.Control(func(fd uintptr) {
		cred, err = syscall.GetsockoptUcred(int(fd),
			syscall.SOL_SOCKET,
			syscall.SO_PEERCRED)
	})
	return cred, err
}

func checkSystemd() bool {
	if invocationID := os.Getenv("INVOCATION_ID"); invocationID != "" {
		ppid := os.Getppid()
		if ppid == 1 { // NOTE: PID 1 is systemd in any linux system worth its salt
			return true
		}
	}
	return false
}
