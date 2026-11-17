// Package sandbox runs restores in throwaway Docker containers with no
// network, resource limits, a minimal capability set and guaranteed cleanup
// (deferred removal, labels, and a TTL reaper that runs at the start of every
// verify). It drives the docker CLI, so it works with Docker Engine, Docker
// Desktop, colima or any other runtime that provides a docker-compatible CLI.
package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const (
	LabelManaged = "xinproof.managed"
	LabelRun     = "xinproof.run"
	LabelExpires = "xinproof.expires"
	LabelPID     = "xinproof.pid"  // process that created the sandbox
	LabelHost    = "xinproof.host" // host that process ran on
)

type Docker struct {
	Bin string       // docker binary; "docker" if empty
	Log *slog.Logger // nil discards
}

func (d *Docker) log() *slog.Logger {
	if d.Log != nil {
		return d.Log
	}
	return slog.New(slog.DiscardHandler)
}

func (d *Docker) bin() string {
	if d.Bin == "" {
		return "docker"
	}
	return d.Bin
}

// ErrUnavailable means the container runtime cannot be used at all.
var ErrUnavailable = errors.New("docker is not available")

// Available checks that the docker CLI exists and can reach a daemon.
func (d *Docker) Available(ctx context.Context) error {
	if _, err := exec.LookPath(d.bin()); err != nil {
		return fmt.Errorf("%w: %q not found on PATH (install Docker Engine, or Docker Desktop on macOS/Windows)", ErrUnavailable, d.bin())
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	out, err := d.run(ctx, nil, "version", "--format", "{{.Server.Version}}")
	if err != nil {
		return fmt.Errorf("%w: cannot reach the Docker daemon (%s)", ErrUnavailable, firstLine(out, err))
	}
	return nil
}

// EnsureImage makes sure image is present locally (pulling it if needed) and
// returns its repo digest ("postgres@sha256:…") when known.
func (d *Docker) EnsureImage(ctx context.Context, image string) (string, error) {
	if _, err := d.run(ctx, nil, "image", "inspect", "--format", "{{.Id}}", image); err != nil {
		d.log().Info("pulling sandbox image", "image", image)
		if out, err := d.run(ctx, nil, "pull", "--quiet", image); err != nil {
			return "", fmt.Errorf("cannot pull sandbox image %s: %s", image, firstLine(out, err))
		}
	}
	out, err := d.run(ctx, nil, "image", "inspect", "--format", "{{json .RepoDigests}}", image)
	if err != nil {
		return "", nil
	}
	var digests []string
	if json.Unmarshal(bytes.TrimSpace(out), &digests) == nil && len(digests) > 0 {
		return digests[0], nil
	}
	return "", nil
}

type Spec struct {
	Name      string
	Image     string
	RunID     string
	TTL       time.Duration // after this the reaper may remove the container
	Env       []string      // KEY=VALUE; values are passed via the CLI's environment, never argv
	Memory    string        // e.g. "2g"
	CPUs      string        // e.g. "2"
	PidsLimit int
	TmpfsPath string // optional tmpfs mount point
	TmpfsSize string // e.g. "1g"
	CapAdd    []string
	Args      []string // arguments after the image (the server's command-line options)
}

type Container struct {
	d    *Docker
	Name string
}

// Run starts a detached container. The returned Container is non-nil even on
// error so the caller can always Remove it.
func (d *Docker) Run(ctx context.Context, s Spec) (*Container, error) {
	c := &Container{d: d, Name: s.Name}
	args := []string{"run", "-d", "--name", s.Name,
		"--label", LabelManaged + "=true",
		"--label", LabelRun + "=" + s.RunID,
		"--label", fmt.Sprintf("%s=%d", LabelExpires, time.Now().Add(s.TTL).Unix()),
		"--label", fmt.Sprintf("%s=%d", LabelPID, os.Getpid()),
		"--label", LabelHost + "=" + hostname(),
		"--network", "none",
		"--security-opt", "no-new-privileges",
		"--cap-drop", "ALL",
	}
	for _, cap := range s.CapAdd {
		args = append(args, "--cap-add", cap)
	}
	if s.Memory != "" {
		args = append(args, "--memory", s.Memory, "--memory-swap", s.Memory)
	}
	if s.CPUs != "" {
		args = append(args, "--cpus", s.CPUs)
	}
	if s.PidsLimit > 0 {
		args = append(args, "--pids-limit", strconv.Itoa(s.PidsLimit))
	}
	if s.TmpfsPath != "" {
		opt := s.TmpfsPath + ":rw,mode=1777"
		if s.TmpfsSize != "" {
			opt += ",size=" + s.TmpfsSize
		}
		args = append(args, "--tmpfs", opt)
	}
	var env []string
	for _, kv := range s.Env {
		k, _, _ := strings.Cut(kv, "=")
		args = append(args, "-e", k)
		env = append(env, kv)
	}
	args = append(args, s.Image)
	args = append(args, s.Args...)
	d.log().Debug("sandbox start", "container", s.Name, "image", s.Image, "memory", s.Memory, "cpus", s.CPUs, "tmpfs", s.TmpfsSize)
	if out, err := d.run(ctx, env, args...); err != nil {
		d.log().Warn("sandbox start failed", "container", s.Name, "error", firstLine(out, err))
		return c, fmt.Errorf("cannot start sandbox container: %s", firstLine(out, err))
	}
	return c, nil
}

type ExecOpts struct {
	Args   []string
	Stdin  io.Reader
	Stdout io.Writer // if nil, stdout is captured into ExecResult.Stdout (up to 64 MiB)
	User   string
	Env    []string // KEY=VALUE for this command only; values travel via the CLI's environment, never argv
}

type ExecResult struct {
	ExitCode int
	Stdout   []byte
	Stderr   string // first 64 KiB
}

// DaemonError reports whether a non-zero exit came from docker itself rather
// than the command (for example because the container died).
func (r ExecResult) DaemonError() bool {
	return r.ExitCode != 0 && strings.Contains(r.Stderr, "Error response from daemon")
}

// Exec runs a command in the container. err is non-nil only if docker could
// not be run; a failing command is reported through ExitCode.
func (c *Container) Exec(ctx context.Context, o ExecOpts) (ExecResult, error) {
	args := []string{"exec"}
	if o.Stdin != nil {
		args = append(args, "-i")
	}
	if o.User != "" {
		args = append(args, "-u", o.User)
	}
	for _, kv := range o.Env {
		k, _, _ := strings.Cut(kv, "=")
		args = append(args, "-e", k)
	}
	args = append(args, c.Name)
	args = append(args, o.Args...)
	cmd := exec.CommandContext(ctx, c.d.bin(), args...)
	cmd.Stdin = o.Stdin
	if len(o.Env) > 0 {
		cmd.Env = append(os.Environ(), o.Env...)
	}
	stdout := &capBuffer{max: 64 << 20}
	if o.Stdout != nil {
		cmd.Stdout = o.Stdout
	} else {
		cmd.Stdout = stdout
	}
	stderr := &capBuffer{max: 64 << 10}
	cmd.Stderr = stderr
	err := cmd.Run()
	res := ExecResult{Stdout: stdout.Bytes(), Stderr: stderr.String()}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		res.ExitCode = ee.ExitCode()
		return res, nil
	}
	if err != nil {
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		return res, err
	}
	return res, nil
}

// Running reports whether the container is still running.
func (c *Container) Running(ctx context.Context) bool {
	out, err := c.d.run(ctx, nil, "inspect", "--format", "{{.State.Running}}", c.Name)
	return err == nil && strings.TrimSpace(string(out)) == "true"
}

// Died explains why a container that should be running isn't (killed, out
// of memory, gone). It returns "" if the container is still running. It uses
// its own context so it works after the caller's deadline.
func (c *Container) Died() string {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	out, err := c.d.run(ctx, nil, "inspect", "--format", "{{.State.Running}} {{.State.OOMKilled}} {{.State.ExitCode}}", c.Name)
	if err != nil {
		return "the sandbox container disappeared"
	}
	f := strings.Fields(string(out))
	if len(f) != 3 || f[0] == "true" {
		return ""
	}
	if f[1] == "true" {
		return "the sandbox ran out of memory and was killed (raise --memory)"
	}
	return "the sandbox container stopped (exit code " + f[2] + ")"
}

// Logs returns the last lines of the container's output, for error messages.
func (c *Container) Logs(ctx context.Context, lines int) string {
	out, _ := c.d.run(ctx, nil, "logs", "--tail", strconv.Itoa(lines), c.Name)
	return strings.TrimSpace(string(out))
}

// Remove force-removes the container and its anonymous volumes. It uses its
// own short timeout so it still runs after the caller's context is cancelled.
func (c *Container) Remove() error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out, err := c.d.run(ctx, nil, "rm", "-f", "-v", c.Name)
	if err != nil && !strings.Contains(string(out), "No such container") {
		c.d.log().Error("sandbox removal failed; the reaper will retry on the next run", "container", c.Name, "error", firstLine(out, err))
		return fmt.Errorf("removing sandbox %s: %s", c.Name, firstLine(out, err))
	}
	c.d.log().Debug("sandbox removed", "container", c.Name)
	return nil
}

// Reap removes sandboxes left behind by runs that were killed: those whose
// creating process (on this host) no longer exists, and any whose TTL has
// expired. Sandboxes of other live runs are left alone. It returns how many
// it removed.
func (d *Docker) Reap(ctx context.Context) (int, error) {
	out, err := d.run(ctx, nil, "ps", "-a", "--filter", "label="+LabelManaged+"=true",
		"--format", `{{.Names}}	{{.Label "`+LabelExpires+`"}}	{{.Label "`+LabelPID+`"}}	{{.Label "`+LabelHost+`"}}`)
	if err != nil {
		return 0, fmt.Errorf("listing old sandboxes: %s", firstLine(out, err))
	}
	now := time.Now().Unix()
	host := hostname()
	n := 0
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Split(line, "\t")
		if len(f) < 2 {
			continue
		}
		name := f[0]
		ts, err := strconv.ParseInt(strings.TrimSpace(f[1]), 10, 64)
		expired := err == nil && ts <= now
		orphaned := false
		if len(f) == 4 && f[3] == host {
			if pid, err := strconv.Atoi(f[2]); err == nil && pid != os.Getpid() && !processAlive(pid) {
				orphaned = true
			}
		}
		if !expired && !orphaned {
			continue
		}
		if (&Container{d: d, Name: name}).Remove() == nil {
			d.log().Info("reaped leftover sandbox", "container", name, "expired", expired, "orphaned", orphaned)
			n++
		}
	}
	return n, nil
}

func (d *Docker) run(ctx context.Context, env []string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, d.bin(), args...)
	if env != nil {
		cmd.Env = append(os.Environ(), env...)
	}
	return cmd.CombinedOutput()
}

func firstLine(out []byte, err error) string {
	s := strings.TrimSpace(string(out))
	if s == "" {
		return err.Error()
	}
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}

// capBuffer keeps the first max bytes written and discards the rest.
type capBuffer struct {
	bytes.Buffer
	max int
}

func (b *capBuffer) Write(p []byte) (int, error) {
	if room := b.max - b.Len(); room > 0 {
		if len(p) > room {
			b.Buffer.Write(p[:room])
		} else {
			b.Buffer.Write(p)
		}
	}
	return len(p), nil
}
