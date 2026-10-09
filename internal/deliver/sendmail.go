package deliver

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/brodyhoskins/mailcloak/internal/pipeline"
)

// Sendmail reinjects a message with the MTA's sendmail(1) command. This is how
// a pipe-mode filter hands mail back to Postfix.
type Sendmail struct {
	Path string   // e.g. /usr/sbin/sendmail
	Args []string // extra arguments before -f, e.g. ["-G", "-i"] for Postfix
}

func (s *Sendmail) Handle(ctx context.Context, env *pipeline.Envelope) error {
	from := env.From
	if from == "" {
		from = "<>" // null sender, e.g. a bounce
	}
	args := append(append([]string{}, s.Args...), "-f", from, "--")
	args = append(args, env.To...)

	cmd := exec.CommandContext(ctx, s.Path, args...)
	cmd.Stdin = bytes.NewReader(env.Data)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		// Any reinjection failure is treated as temporary: the message is
		// still safe in the MTA's queue and will be retried.
		return fmt.Errorf("sendmail: %w: %s", err, strings.TrimSpace(out.String()))
	}
	return nil
}
