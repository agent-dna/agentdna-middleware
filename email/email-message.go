package email

import (
	"bytes"
	"fmt"
	"html/template"
)

// APIKeyDelivery renders the email a new user receives with their freshly
// issued API key. Adjust the template below to change branding/copy.
func APIKeyDelivery(toEmail, apiKey string) (Message, error) {
	data := struct {
		Email  string
		APIKey string
	}{toEmail, apiKey}
	html, err := render(apiKeyDeliveryTmpl, data)
	if err != nil {
		return Message{}, err
	}
	return Message{
		To:      toEmail,
		Subject: "Your AgentDNA API key",
		HTML:    html,
	}, nil
}

var apiKeyDeliveryTmpl = template.Must(template.New("apikey").Parse(`
<!doctype html>
<html>
<body style="font-family:Inter,Arial,sans-serif;background:#ffffff;color:#0f172a;padding:24px;max-width:560px;margin:0 auto">
  <h2 style="margin:0 0 16px 0">Welcome to AgentDNA</h2>
  <p>Hi {{.Email}},</p>
  <p>Your API key has been issued. Keep it private — it grants access to your account.</p>
  <pre style="background:#f1f5f9;border:1px solid #e2e8f0;padding:14px;border-radius:8px;font-family:Menlo,Consolas,monospace;font-size:13px;word-break:break-all;white-space:pre-wrap">{{.APIKey}}</pre>
  <p>Use it via the <code>X-API-Key</code> header on your requests to the AgentDNA proxy.</p>
  <p style="color:#64748b;font-size:12px;margin-top:32px">If you didn't request this key, please ignore this message.</p>
</body>
</html>
`))

func render(t *template.Template, data any) (string, error) {
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("render template %q: %w", t.Name(), err)
	}
	return buf.String(), nil
}
