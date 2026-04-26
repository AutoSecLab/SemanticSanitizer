package tracepipe

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
)

var candidatePaths = []string{
	"/sys/kernel/tracing/trace_pipe",
	"/sys/kernel/debug/tracing/trace_pipe",
}

// Follow tails trace_pipe until the context is done and writes bpf_printk
// messages to out.
func Follow(ctx context.Context, out io.Writer) error {
	f, path, err := openTracePipe()
	if err != nil {
		return err
	}
	defer f.Close()

	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = f.Close()
		case <-done:
		}
	}()
	defer close(done)

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		msg, ok := extractPrintkMessage(line)
		if !ok {
			continue
		}
		if _, err := fmt.Fprintln(out, msg); err != nil {
			return fmt.Errorf("write trace_pipe output: %w", err)
		}
	}

	if err := scanner.Err(); err != nil && ctx.Err() == nil {
		return fmt.Errorf("read %s: %w", path, err)
	}

	return nil
}

func openTracePipe() (*os.File, string, error) {
	var errs []string
	for _, path := range candidatePaths {
		f, err := os.Open(path)
		if err == nil {
			return f, path, nil
		}
		errs = append(errs, fmt.Sprintf("%s: %v", path, err))
	}

	return nil, "", fmt.Errorf("open trace_pipe: %s", strings.Join(errs, "; "))
}

func extractPrintkMessage(line string) (string, bool) {
	const marker = "bpf_trace_printk: "
	idx := strings.Index(line, marker)
	if idx < 0 {
		return "", false
	}

	return line[idx+len(marker):], true
}
