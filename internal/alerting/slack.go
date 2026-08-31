// Package alerting delivers security alerts to external sinks. The MVP supports a
// single sink (Slack via incoming webhook); the design leaves room for more sinks
// (email, PagerDuty, webhook) in V2 without disturbing callers.
//
// The Send function reads the webhook URL from an environment variable — it is
// NEVER passed in configuration on disk, in line with the project's secret-handling
// principles. When the env var is empty or unset, Send is a silent no-op so the
// scanner runs end-to-end in environments without Slack configured.
//
// Alert delivery failures do not abort the scan — the alert is already persisted
// in SQLite before delivery is attempted, so it can be retried or viewed with
// `depwatch alerts`.
package alerting

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/yourpwnguy/depwatch/internal/domain"
)

// Send posts an alert to Slack using an incoming webhook. The webhook URL is read
// from the environment variable named by webhookEnv. When webhookEnv is empty or
// the variable is unset, Send is a silent no-op.
//
// The payload uses Slack's Block Kit format for rich rendering. The fallback text
// field ensures the message is readable even in notifications or plain-text clients.
func Send(ctx context.Context, webhookEnv string, a *domain.Alert) error {
	if webhookEnv == "" {
		return nil
	}
	url := os.Getenv(webhookEnv)
	if url == "" {
		return nil
	}

	payload := map[string]any{
		"text": fmt.Sprintf("[%s] Dependency confusion risk: %s (%s)", a.Risk, a.PackageName, a.Registry),
		"blocks": []map[string]any{
			{
				"type": "section",
				"text": map[string]any{
					"type": "mrkdwn",
					"text": alertText(a),
				},
			},
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal alert: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("slack post: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("slack returned %d", resp.StatusCode)
	}
	return nil
}

// alertText renders a compact, human-readable summary of the alert for Slack.
// Each signal is listed with its severity in brackets so the Slack message
// provides the same evidence context as the terminal output.
func alertText(a *domain.Alert) string {
	var msg strings.Builder
	fmt.Fprintf(&msg, "*[%s] %s*\nPackage: `%s`\nRegistry: `%s`\nType: %s",
		a.Risk, "Dependency Confusion Risk", a.PackageName, a.Registry, a.Type)
	for _, s := range a.Signals {
		fmt.Fprintf(&msg, "\n• [%s] %s", s.Severity, s.Message)
	}
	return msg.String()
}
