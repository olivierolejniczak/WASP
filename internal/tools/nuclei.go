package tools

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
)

// NucleiTool wraps nuclei for template-based vulnerability scanning.
type NucleiTool struct{}

func NewNucleiTool() *NucleiTool { return &NucleiTool{} }

func (n *NucleiTool) Name() string { return "nuclei" }

func (n *NucleiTool) IsAvailable() bool { return IsCommandAvailable("nuclei") }

func (n *NucleiTool) Run(ctx context.Context, target string, opts Options) (*ToolResult, error) {
	scopeDef := getScopeFromContext(ctx)
	if scopeDef != nil {
		if err := scope.ValidateAndLog("nuclei", target, *scopeDef); err != nil {
			return nil, fmt.Errorf("scope violation in nuclei: %w", err)
		}
	}

	timeout := time.Duration(opts.GetInt("timeout", 300)) * time.Second

	severity := opts.GetStringSlice("severity")
	if severity == nil {
		severity = []string{"critical", "high", "medium"}
	}

	// Resolve focused template subdirectories. Using the top-level
	// ~/nuclei-templates dir causes nuclei to recurse into cloud/code
	// protocol templates that trigger an interactive auth prompt in
	// non-TTY contexts. Limiting to known-safe HTTP subdirs avoids this
	// and keeps scan time under 5 minutes on a CPU-only host.
	home, _ := os.UserHomeDir()
	base := strings.TrimSpace(home) + "/nuclei-templates"
	focusedDirs := []string{
		base + "/http/exposures",
		base + "/http/misconfiguration",
		base + "/http/technologies",
		base + "/http/vulnerabilities",
		base + "/http/takeovers",
	}
	var templateArgs []string
	for _, dir := range focusedDirs {
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			templateArgs = append(templateArgs, "-t", dir)
		}
	}

	// Nuclei v3 replaced the legacy `-json` flag with `-jsonl` (JSON-Lines).
	// -duc            disable update check (no extra network round-trip).
	// -no-interactsh  skip OOB callbacks — avoids hanging on air-gapped hosts.
	// -rl / -c        conservative rate + concurrency for CPU-only hosts.
	args := []string{
		"-u", target,
		"-jsonl", "-silent",
		"-severity", strings.Join(severity, ","),
		"-duc",
		"-no-interactsh",
		"-rl", "30",
		"-c", "5",
		"-timeout", "8",
	}
	args = append(args, templateArgs...)

	result := RunToolCommand(ctx, "nuclei", target, timeout, "nuclei", args...)
	return result, result.Error
}
