package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/msanft/SemanticSanitizer/internal/attach"
	"github.com/msanft/SemanticSanitizer/internal/config"
	"github.com/msanft/SemanticSanitizer/internal/tracepipe"
	"github.com/spf13/cobra"
)

func NewAttachCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "attach",
		Short: "attach the sanitizer",
		Long:  "TODO",
		RunE:  runAttach,
	}

	cmd.Flags().StringP("config", "c", config.DefaultPath, "path to the configuration file")
	cmd.Flags().Bool("trace-pipe", false, "tail trace_pipe and print bpf_printk output to the CLI")
	cmd.MarkFlagFilename("config")

	return cmd
}

func runAttach(cmd *cobra.Command, args []string) error {
	configPath, err := cmd.Flags().GetString("config")
	if err != nil {
		return fmt.Errorf("get config flag: %w", err)
	}

	conf, err := config.NewFromFile(configPath)
	if err != nil {
		return fmt.Errorf("read config file: %w", err)
	}

	tracePipe, err := cmd.Flags().GetBool("trace-pipe")
	if err != nil {
		return fmt.Errorf("get trace-pipe flag: %w", err)
	}
	if tracePipe {
		go func() {
			if err := tracepipe.Follow(cmd.Context(), os.Stdout); err != nil && !errors.Is(err, cmd.Context().Err()) {
				fmt.Fprintf(os.Stderr, "trace_pipe: %v\n", err)
			}
		}()
	}

	allRunning := make(chan struct{})
	defer close(allRunning)
	go func() {
		<-allRunning
		fmt.Println("All sanitizers are running")
	}()

	if err = attach.AttachContext(cmd.Context(), conf, allRunning); err != nil {
		return fmt.Errorf("attach sanitizer: %w", err)
	}

	return nil
}
