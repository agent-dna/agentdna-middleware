package email

import (
	"fmt"
	"os"

	"github.com/resend/resend-go/v3"
)

// Config holds the Resend credentials and sender identity used by the Mailer.
type Config struct {
	APIKey string
	From   string
}


func LoadConfigFromEnv() (Config, error) {
	cfg := Config{
		APIKey: os.Getenv("RESEND_API_KEY"),
		From:   os.Getenv("EMAIL_FROM"),
	}
	if cfg.APIKey == "" || cfg.From == "" {
		return cfg, fmt.Errorf("RESEND_API_KEY and EMAIL_FROM must be set")
	}
	return cfg, nil
}

// Mailer sends rendered Messages via Resend.
type Mailer struct {
	client *resend.Client
	from   string
}

func New(cfg Config) *Mailer {
	return &Mailer{
		client: resend.NewClient(cfg.APIKey),
		from:   cfg.From,
	}
}

// Message is a rendered, ready-to-send email. Construct one with a builder
// from email-message.go (e.g. APIKeyDelivery).
type Message struct {
	To      string
	Subject string
	HTML    string
}

// Send delivers msg through Resend.
func (m *Mailer) Send(msg Message) error {
	_, err := m.client.Emails.Send(&resend.SendEmailRequest{
		From:    m.from,
		To:      []string{msg.To},
		Subject: msg.Subject,
		Html:    msg.HTML,
	})
	if err != nil {
		return fmt.Errorf("resend send to %s: %w", msg.To, err)
	}
	return nil
}
