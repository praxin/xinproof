package conformance

import (
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Emulator images used in tests (pinned by tag; CI pulls them).
const (
	// S3-compatible store for tests. MinIO no longer publishes images, so
	// SeaweedFS's S3 gateway stands in (anonymous access when unconfigured).
	S3Image      = "chrislusf/seaweedfs:latest"
	AzuriteImage = "mcr.microsoft.com/azure-storage/azurite:latest"
	FakeGCSImage = "fsouza/fake-gcs-server:latest"
)

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// StartEmulator runs image with containerPort published on a free localhost
// port and returns "http://127.0.0.1:<port>". args may contain {PORT}, which
// is replaced by the host port (some emulators must know their public URL).
// The container is removed when the test ends. Skips without Docker or with -short.
func StartEmulator(t *testing.T, image string, containerPort int, readyPath string, args ...string) string {
	t.Helper()
	if testing.Short() {
		t.Skip("emulator test (needs Docker); skipped with -short")
	}
	if err := exec.Command("docker", "version").Run(); err != nil {
		t.Skip("skipping: docker not available")
	}
	port := freePort(t)
	if containerPort == 0 {
		containerPort = port
	}
	name := fmt.Sprintf("xinproof-emu-%d", port)
	run := []string{"run", "-d", "--rm", "--name", name,
		"--label", "xinproof.managed=true", "--label", fmt.Sprintf("xinproof.expires=%d", time.Now().Add(30*time.Minute).Unix()),
		"-p", fmt.Sprintf("127.0.0.1:%d:%d", port, containerPort), image}
	for _, a := range args {
		run = append(run, strings.ReplaceAll(a, "{PORT}", strconv.Itoa(port)))
	}
	if out, err := exec.Command("docker", run...).CombinedOutput(); err != nil {
		t.Fatalf("starting %s: %v\n%s", image, err, out)
	}
	t.Cleanup(func() { exec.Command("docker", "rm", "-f", name).Run() })
	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	deadline := time.Now().Add(90 * time.Second)
	for {
		resp, err := http.Get(base + readyPath)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode < 500 {
				return base
			}
		}
		if time.Now().After(deadline) {
			logs, _ := exec.Command("docker", "logs", "--tail", "20", name).CombinedOutput()
			t.Fatalf("%s not ready at %s: %v\n%s", image, base, err, logs)
		}
		time.Sleep(300 * time.Millisecond)
	}
}
