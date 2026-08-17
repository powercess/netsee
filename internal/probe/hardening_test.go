//go:build linux

package probe

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"netsee/internal/client"
)

var probeBin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "netsee-hardening")
	if err != nil {
		panic(err)
	}
	probeBin = filepath.Join(dir, "netsee-probe")
	cmd := exec.Command("go", "build", "-o", probeBin, "netsee/cmd/probe")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "build probe: %v: %s\n", err, out)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

var listenLogRe = regexp.MustCompile(`http=127\.0\.0\.1:(\d+) tls=127\.0\.0\.1:(\d+) udp=127\.0\.0\.1:(\d+) nat=127\.0\.0\.1:(\d+)`)

// startProbeProc launches the probe binary in a fresh cwd and returns the
// process, its actual ports, and a cleanup func.
func startProbeProc(t *testing.T) (*exec.Cmd, [4]int, string) {
	t.Helper()
	cwd := t.TempDir()
	cmd := exec.Command(probeBin, "-bind", "127.0.0.1",
		"-http-port", "0", "-tls-port", "0", "-udp-port", "0", "-nat-port", "0", "-ttl", "5m")
	cmd.Dir = cwd
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout = os.Stdout
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })

	// Wait for the startup line carrying the actual bound ports
	// (log.Printf writes to stderr).
	lineCh := make(chan string, 1)
	go func() {
		r := bufio.NewReader(stderr)
		for {
			line, err := r.ReadString('\n')
			if line != "" {
				lineCh <- line
				if m := listenLogRe.FindStringSubmatch(line); m != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	select {
	case line := <-lineCh:
		m := listenLogRe.FindStringSubmatch(line)
		if m == nil {
			t.Fatalf("startup line missing ports: %q", line)
		}
		var ports [4]int
		for i := 0; i < 4; i++ {
			ports[i], _ = strconv.Atoi(m[i+1])
		}
		return cmd, ports, cwd
	case <-time.After(15 * time.Second):
		t.Fatal("probe did not report listening ports")
		return nil, [4]int{}, ""
	}
}

// TestProbeZeroWritesAndMinimalSurface verifies ACC-P5-003 (zero disk
// writes) and ACC-P5-004 (minimal listening surface): after a full
// measurement the probe's working directory must stay empty, and its only
// bound sockets must be the four declared ports.
func TestProbeZeroWritesAndMinimalSurface(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires /proc")
	}
	cmd, ports, cwd := startProbeProc(t)
	pid := cmd.Process.Pid

	// Run a full client measurement against the subprocess probe.
	cfg := client.Config{
		ProbeURL:  fmt.Sprintf("http://127.0.0.1:%d", ports[0]),
		Timeout:   5 * time.Second,
		DoHURL:    "",
		IPAPIBase: "http://127.0.0.1:1/json",
	}
	if _, err := cfg.Run(context.Background()); err != nil {
		t.Fatalf("client run against subprocess probe: %v", err)
	}

	// ACC-P5-003: no files written to the working directory.
	entries, err := os.ReadDir(cwd)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("probe wrote files to cwd: %v", names)
	}

	// ACC-P5-004: only the four declared ports are bound.
	got := probeBoundPorts(t, pid)
	want := map[int]bool{}
	for _, p := range ports {
		want[p] = true
	}
	if len(got) != len(want) {
		t.Errorf("bound ports = %v, want %v", sortedPorts(got), sortedPorts(want))
	}
	for p := range want {
		if !got[p] {
			t.Errorf("missing listener on declared port %d (got %v)", p, sortedPorts(got))
		}
	}
	for p := range got {
		if !want[p] {
			t.Errorf("unexpected listener on port %d (want only %v)", p, sortedPorts(want))
		}
	}
}

// probeBoundPorts returns the ports of all sockets held by the process,
// resolved through /proc/<pid>/fd → socket inode → /proc/net local port.
func probeBoundPorts(t *testing.T, pid int) map[int]bool {
	t.Helper()
	inodePort := map[string]int{}
	for _, file := range []string{"tcp", "tcp6", "udp", "udp6"} {
		data, err := os.ReadFile("/proc/net/" + file)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n")[1:] {
			fields := strings.Fields(line)
			if len(fields) < 10 {
				continue
			}
			// fields[1] = local_address "HEXIP:HEXPORT", fields[9] = inode
			addr := fields[1]
			i := strings.LastIndexByte(addr, ':')
			if i < 0 {
				continue
			}
			p, err := strconv.ParseUint(addr[i+1:], 16, 32)
			if err != nil || p == 0 {
				continue
			}
			inodePort[fields[9]] = int(p)
		}
	}
	fds, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		t.Fatalf("read /proc/%d/fd: %v", pid, err)
	}
	ports := map[int]bool{}
	for _, fd := range fds {
		target, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, fd.Name()))
		if err != nil || !strings.HasPrefix(target, "socket:[") {
			continue
		}
		inode := strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
		if p, ok := inodePort[inode]; ok {
			ports[p] = true
		}
	}
	return ports
}

func sortedPorts(m map[int]bool) []int {
	out := make([]int, 0, len(m))
	for p := range m {
		out = append(out, p)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
