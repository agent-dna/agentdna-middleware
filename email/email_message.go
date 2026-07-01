package email

import (
	"bytes"
	"fmt"
	"html/template"
	"os"
	"time"
)

// UserRegistration sends a welcome email to a newly registered user.
func UserRegistration(toEmail, name string) (Message, error) {
	if name == "" {
		name = "there"
	}
	data := struct {
		Name         string
		Email        string
		DashboardURL string
		Year         int
	}{
		Name:         name,
		Email:        toEmail,
		DashboardURL: envOr("APP_DASHBOARD_URL", "#"),
		Year:         time.Now().Year(),
	}
	html, err := render(userRegistrationTmpl, data)
	if err != nil {
		return Message{}, err
	}
	return Message{
		To:      toEmail,
		Subject: "Welcome to AgentDNA — your account is ready",
		HTML:    html,
	}, nil
}

var userRegistrationTmpl = template.Must(template.New("user-registration").Parse(`
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1.0"/>
  <title>Welcome to AgentDNA</title>
  <style>
    body{margin:0;padding:0;background:#F0F4F9;font-family:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;}
    @media only screen and (max-width:600px){.wrapper{width:100%!important}.body-pad{padding:28px 20px 32px!important}}
  </style>
</head>
<body>
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#F0F4F9;padding:40px 16px;">
    <tr><td align="center" valign="top">

      <table class="wrapper" role="presentation" width="580" cellpadding="0" cellspacing="0" border="0"
             style="max-width:580px;width:100%;background:#fff;border-radius:16px;border:1px solid #DCE6F4;box-shadow:0 4px 24px -8px rgba(10,34,64,.10);">

        <!-- accent line -->
        <tr><td style="background:linear-gradient(90deg,#2D7DFF 0%,#6BA8FF 100%);height:3px;border-radius:16px 16px 0 0;font-size:0;line-height:0;">&nbsp;</td></tr>

        <!-- logo -->
        <tr>
          <td style="padding:32px 40px 0;">
            <a href="https://agentdna.io" target="_blank" rel="noopener noreferrer" style="display:inline-block;text-decoration:none;">
              <img src="https://agentdna.io/assets/wb-BuhqEaFf.png" alt="AgentDNA" height="36" style="height:36px;width:auto;display:block;"/>
            </a>
          </td>
        </tr>

        <!-- body -->
        <tr>
          <td class="body-pad" style="padding:32px 40px 40px;">

            <!-- pill -->
            <table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin-bottom:20px;">
              <tr><td style="background:#DCFCE7;border-radius:999px;padding:5px 12px;">
                <p style="margin:0;font-size:11px;font-weight:600;color:#15803D;text-transform:uppercase;letter-spacing:.14em;line-height:1;">&#9679;&ensp;Account Created</p>
              </td></tr>
            </table>

            <h1 style="margin:0 0 10px;font-size:30px;font-weight:800;line-height:1.15;color:#0A2240;letter-spacing:-.025em;">
              Welcome aboard, {{.Name}}!
            </h1>

            <p style="margin:0 0 16px;font-size:15.5px;color:#0E1A2B;line-height:1.7;">
              Congratulations — your AgentDNA account has been successfully created.
            </p>
            <p style="margin:0 0 24px;font-size:15.5px;color:#0E1A2B;line-height:1.7;">
              You now have access to the dashboard where you can monitor your agents, review interactions, manage requests, and much more.
            </p>

            <!-- info box -->
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"
                   style="background:#F6F9FE;border:1.5px solid #DCE6F4;border-radius:12px;margin-bottom:28px;">
              <tr><td style="padding:22px 26px;">
                <p style="margin:0 0 6px;font-size:11px;font-weight:600;color:#1D5FD9;text-transform:uppercase;letter-spacing:.14em;">Registered email</p>
                <p style="margin:0;font-size:15px;font-weight:500;color:#0A2240;">{{.Email}}</p>
              </td></tr>
            </table>

            <!-- CTA -->
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-bottom:28px;">
              <tr><td align="center">
                <a href="{{.DashboardURL}}" target="_blank" rel="noopener noreferrer"
                   style="display:inline-block;background:#2D7DFF;color:#fff;text-decoration:none;font-size:14.5px;font-weight:600;padding:13px 32px;border-radius:999px;box-shadow:0 8px 24px -8px rgba(45,125,255,.55);">
                  Go to Dashboard &rarr;
                </a>
              </td></tr>
            </table>

            <!-- divider -->
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-bottom:24px;">
              <tr><td style="border-top:1px solid #EDF3FB;font-size:0;line-height:0;">&nbsp;</td></tr>
            </table>

            <p style="margin:0 0 2px;font-size:15.5px;color:#475569;line-height:1.7;">Thanks &amp; regards,</p>
            <p style="margin:0;font-size:15.5px;font-weight:700;color:#0A2240;line-height:1.7;">The AgentDNA Team</p>

          </td>
        </tr>

        <!-- footer -->
        <tr>
          <td style="background:#F6F9FE;border-top:1px solid #EDF3FB;padding:20px 40px;border-radius:0 0 16px 16px;">
            <p style="margin:0;font-size:11.5px;color:#94A3B8;text-align:center;line-height:1.6;">
              You received this because you registered on AgentDNA.
            </p>
            <p style="margin:6px 0 0;font-size:11.5px;color:#94A3B8;text-align:center;">
              &copy; {{.Year}} AgentDNA, Inc. &nbsp;&bull;&nbsp;
              <a href="https://agentdna.io" style="color:#2D7DFF;text-decoration:none;">agentdna.io</a>
            </p>
          </td>
        </tr>

      </table>
    </td></tr>
  </table>
</body>
</html>
`))

// APIKeyDelivery renders the welcome email a new beta user receives with
// their private access key. Optional links read from env:
//   APP_ACTIVATION_URL    used by the "Activate Beta Access" CTA (default "#")
//   APP_UNSUBSCRIBE_URL   used by the footer unsubscribe link (default "#")
func APIKeyDelivery(toEmail, name, apiKey string) (Message, error) {
	data := struct {
		Email          string
		Name           string
		APIKey         string
		ActivationURL  string
		UnsubscribeURL string
		Year           int
	}{
		Email:          toEmail,
		Name:           name,
		APIKey:         apiKey,
		ActivationURL:  envOr("APP_ACTIVATION_URL", "#"),
		UnsubscribeURL: envOr("APP_UNSUBSCRIBE_URL", "#"),
		Year:           time.Now().Year(),
	}
	html, err := render(apiKeyDeliveryTmpl, data)
	if err != nil {
		return Message{}, err
	}
	return Message{
		To:      toEmail,
		Subject: "Your agentDNA private beta access key",
		HTML:    html,
	}, nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func render(t *template.Template, data any) (string, error) {
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("render template %q: %w", t.Name(), err)
	}
	return buf.String(), nil
}

// AgentCreationRequestNew is sent to the admin when a user creates a new agent
// creation request.
func AgentCreationRequestNew(toEmail, agentName, requesterName, requestID string) (Message, error) {
	data := struct {
		AgentName     string
		RequesterName string
		RequestID     string
		DashboardURL  string
		Year          int
	}{
		AgentName:     agentName,
		RequesterName: requesterName,
		RequestID:     requestID,
		DashboardURL:  envOr("APP_DASHBOARD_URL", "#"),
		Year:          time.Now().Year(),
	}
	html, err := render(agentRequestNewTmpl, data)
	if err != nil {
		return Message{}, err
	}
	return Message{
		To:      toEmail,
		Subject: fmt.Sprintf("New agent creation request: %s", agentName),
		HTML:    html,
	}, nil
}

// AgentCreationRequestStatus is sent to the user when the admin acts on their
// agent creation request (approved or rejected).
func AgentCreationRequestStatus(toEmail, userName, agentName, status string) (Message, error) {
	data := struct {
		UserName     string
		AgentName    string
		Status       string
		Approved     bool
		DashboardURL string
		Year         int
	}{
		UserName:     userName,
		AgentName:    agentName,
		Status:       status,
		Approved:     status == "approved",
		DashboardURL: envOr("APP_DASHBOARD_URL", "#"),
		Year:         time.Now().Year(),
	}
	html, err := render(agentRequestStatusTmpl, data)
	if err != nil {
		return Message{}, err
	}
	subject := fmt.Sprintf("Your agent request for \"%s\" was %s", agentName, status)
	return Message{To: toEmail, Subject: subject, HTML: html}, nil
}

var agentRequestNewTmpl = template.Must(template.New("agent-request-new").Parse(`
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1.0"/>
  <title>New Agent Request · AgentDNA</title>
  <style>
    body{margin:0;padding:0;background:#F0F4F9;font-family:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;}
    @media only screen and (max-width:600px){.wrapper{width:100%!important}.body-pad{padding:28px 20px 32px!important}}
  </style>
</head>
<body>
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:#F0F4F9;padding:40px 16px;">
    <tr><td align="center" valign="top">
      <table class="wrapper" role="presentation" width="580" cellpadding="0" cellspacing="0" border="0"
             style="max-width:580px;width:100%;background:#fff;border-radius:16px;border:1px solid #DCE6F4;box-shadow:0 4px 24px -8px rgba(10,34,64,.10);">
        <tr><td style="background:linear-gradient(90deg,#2D7DFF 0%,#6BA8FF 100%);height:3px;border-radius:16px 16px 0 0;font-size:0;line-height:0;">&nbsp;</td></tr>
        <tr>
          <td style="padding:32px 40px 0;">
            <a href="https://agentdna.io" target="_blank" rel="noopener noreferrer" style="display:inline-block;text-decoration:none;">
              <img src="https://agentdna.io/assets/wb-BuhqEaFf.png" alt="AgentDNA" height="36" style="height:36px;width:auto;display:block;"/>
            </a>
          </td>
        </tr>
        <tr>
          <td class="body-pad" style="padding:32px 40px 40px;">
            <table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin-bottom:20px;">
              <tr><td style="background:#EAF2FF;border-radius:999px;padding:5px 12px;">
                <p style="margin:0;font-size:11px;font-weight:600;color:#1D5FD9;text-transform:uppercase;letter-spacing:.14em;line-height:1;">&#9679;&ensp;Admin Alert</p>
              </td></tr>
            </table>
            <h1 style="margin:0 0 20px;font-size:26px;font-weight:800;line-height:1.2;color:#0A2240;letter-spacing:-.02em;">New Agent Creation Request</h1>
            <p style="margin:0 0 16px;font-size:15.5px;color:#0E1A2B;line-height:1.7;">Hi Admin,</p>
            <p style="margin:0 0 20px;font-size:15.5px;color:#0E1A2B;line-height:1.7;">
              A new request has been drafted to create an agent named
              <strong style="color:#0A2240;">{{.AgentName}}</strong> by user
              <strong style="color:#0A2240;">{{.RequesterName}}</strong>.
            </p>
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#F6F9FE;border:1.5px solid #DCE6F4;border-radius:12px;margin-bottom:28px;">
              <tr><td style="padding:22px 26px;">
                <p style="margin:0 0 6px;font-size:11px;font-weight:600;color:#1D5FD9;text-transform:uppercase;letter-spacing:.14em;">Agent Name</p>
                <p style="margin:0 0 16px;font-size:16px;font-weight:700;color:#0A2240;">{{.AgentName}}</p>
                <p style="margin:0 0 6px;font-size:11px;font-weight:600;color:#1D5FD9;text-transform:uppercase;letter-spacing:.14em;">Request ID</p>
                <p style="margin:0;font-size:13px;color:#475569;font-family:'JetBrains Mono','Courier New',monospace;word-break:break-all;">{{.RequestID}}</p>
              </td></tr>
            </table>
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-bottom:28px;">
              <tr><td align="center">
                <a href="{{.DashboardURL}}" target="_blank" rel="noopener noreferrer"
                   style="display:inline-block;background:#2D7DFF;color:#fff;text-decoration:none;font-size:14.5px;font-weight:600;padding:13px 32px;border-radius:999px;box-shadow:0 8px 24px -8px rgba(45,125,255,.55);">
                  Review Request &rarr;
                </a>
              </td></tr>
            </table>
            <p style="margin:0;font-size:13px;color:#94A3B8;line-height:1.6;">This is an automated notification from AgentDNA.</p>
          </td>
        </tr>
        <tr>
          <td style="background:#F6F9FE;border-top:1px solid #EDF3FB;padding:20px 40px;border-radius:0 0 16px 16px;">
            <p style="margin:0;font-size:11.5px;color:#94A3B8;text-align:center;">&copy; {{.Year}} AgentDNA, Inc. &nbsp;&bull;&nbsp;<a href="https://agentdna.io" style="color:#2D7DFF;text-decoration:none;">agentdna.io</a></p>
          </td>
        </tr>
      </table>
    </td></tr>
  </table>
</body>
</html>
`))

var agentRequestStatusTmpl = template.Must(template.New("agent-request-status").Parse(`
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1.0"/>
  <title>Agent Request Update · AgentDNA</title>
  <style>
    body{margin:0;padding:0;background:#F0F4F9;font-family:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;}
    @media only screen and (max-width:600px){.wrapper{width:100%!important}.body-pad{padding:28px 20px 32px!important}}
  </style>
</head>
<body>
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#F0F4F9;padding:40px 16px;">
    <tr><td align="center" valign="top">
      <table class="wrapper" role="presentation" width="580" cellpadding="0" cellspacing="0" border="0"
             style="max-width:580px;width:100%;background:#fff;border-radius:16px;border:1px solid #DCE6F4;box-shadow:0 4px 24px -8px rgba(10,34,64,.10);">
        <tr><td style="background:{{if .Approved}}linear-gradient(90deg,#22C55E 0%,#4ADE80 100%){{else}}linear-gradient(90deg,#EF4444 0%,#F87171 100%){{end}};height:3px;border-radius:16px 16px 0 0;font-size:0;line-height:0;">&nbsp;</td></tr>
        <tr>
          <td style="padding:32px 40px 0;">
            <a href="https://agentdna.io" target="_blank" rel="noopener noreferrer" style="display:inline-block;text-decoration:none;">
              <img src="https://agentdna.io/assets/wb-BuhqEaFf.png" alt="AgentDNA" height="36" style="height:36px;width:auto;display:block;"/>
            </a>
          </td>
        </tr>
        <tr>
          <td class="body-pad" style="padding:32px 40px 40px;">
            <table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin-bottom:20px;">
              <tr><td style="background:{{if .Approved}}#DCFCE7{{else}}#FEE2E2{{end}};border-radius:999px;padding:5px 12px;">
                <p style="margin:0;font-size:11px;font-weight:600;color:{{if .Approved}}#15803D{{else}}#B91C1C{{end}};text-transform:uppercase;letter-spacing:.14em;line-height:1;">
                  &#9679;&ensp;Request {{.Status}}
                </p>
              </td></tr>
            </table>
            <h1 style="margin:0 0 20px;font-size:26px;font-weight:800;line-height:1.2;color:#0A2240;letter-spacing:-.02em;">
              Your agent request was {{.Status}}
            </h1>
            <p style="margin:0 0 16px;font-size:15.5px;color:#0E1A2B;line-height:1.7;">Hi {{.UserName}},</p>
            <p style="margin:0 0 20px;font-size:15.5px;color:#0E1A2B;line-height:1.7;">
              {{if .Approved}}
                Great news! Your request to create agent <strong>{{.AgentName}}</strong> has been <strong style="color:#15803D;">approved</strong>. The agent is now being set up and will be available shortly.
              {{else}}
                Your request to create agent <strong>{{.AgentName}}</strong> has been <strong style="color:#B91C1C;">rejected</strong>. Please reach out to your administrator for more details.
              {{end}}
            </p>
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-bottom:28px;">
              <tr><td align="center">
                <a href="{{.DashboardURL}}" target="_blank" rel="noopener noreferrer"
                   style="display:inline-block;background:#2D7DFF;color:#fff;text-decoration:none;font-size:14.5px;font-weight:600;padding:13px 32px;border-radius:999px;box-shadow:0 8px 24px -8px rgba(45,125,255,.55);">
                  Go to Dashboard &rarr;
                </a>
              </td></tr>
            </table>
            <p style="margin:0;font-size:13px;color:#94A3B8;line-height:1.6;">This is an automated notification from AgentDNA.</p>
          </td>
        </tr>
        <tr>
          <td style="background:#F6F9FE;border-top:1px solid #EDF3FB;padding:20px 40px;border-radius:0 0 16px 16px;">
            <p style="margin:0;font-size:11.5px;color:#94A3B8;text-align:center;">&copy; {{.Year}} AgentDNA, Inc. &nbsp;&bull;&nbsp;<a href="https://agentdna.io" style="color:#2D7DFF;text-decoration:none;">agentdna.io</a></p>
          </td>
        </tr>
      </table>
    </td></tr>
  </table>
</body>
</html>
`))

var apiKeyDeliveryTmpl = template.Must(template.New("apikey").Parse(`
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <meta http-equiv="X-UA-Compatible" content="IE=edge" />
  <title>Your Beta Access Key : AgentDNA</title>
  <!--[if mso]>
  <noscript><xml><o:OfficeDocumentSettings><o:PixelsPerInch>96</o:PixelsPerInch></o:OfficeDocumentSettings></xml></noscript>
  <![endif]-->
  <style>
    /* Reset */
    body, table, td, a { -webkit-text-size-adjust: 100%; -ms-text-size-adjust: 100%; }
    table, td { mso-table-lspace: 0pt; mso-table-rspace: 0pt; }
    img { -ms-interpolation-mode: bicubic; border: 0; outline: none; text-decoration: none; display: block; }

    /* Base */
    body {
      margin: 0;
      padding: 0;
      background-color: #F0F4F9;
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto,
        'Helvetica Neue', Arial, sans-serif;
    }

    /* Google Fonts — Inter (renders in webmail that loads external CSS) */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');

    /* Mobile */
    @media only screen and (max-width: 600px) {
      .wrapper    { width: 100% !important; }
      .body-pad   { padding: 28px 20px 32px !important; }
      .header-pad { padding: 28px 20px 0 !important; }
      .footer-pad { padding: 20px !important; }
      .key-pad    { padding: 18px !important; }
      .key-mono   { font-size: 13px !important; letter-spacing: 1px !important; }
      .h1         { font-size: 26px !important; }
      .cta-btn    { display: block !important; width: 100% !important;
                    box-sizing: border-box !important; text-align: center !important; }
      .logo-img   { height: 32px !important; }
    }
  </style>
</head>
<body>
  <!-- Hidden preview text -->
  <div style="display:none;max-height:0;overflow:hidden;font-size:1px;line-height:1px;color:#F0F4F9;mso-hide:all;">
    Your private beta access key is ready — keep it safe and don't share it.&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;
  </div>

  <!-- Outer background -->
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"
         style="background-color:#F0F4F9; padding:40px 16px;">
    <tr>
      <td align="center" valign="top">

        <!-- Email card -->
        <table class="wrapper" role="presentation" width="580" cellpadding="0" cellspacing="0" border="0"
               style="max-width:580px; width:100%; background-color:#ffffff;
                      border-radius:16px; border:1px solid #DCE6F4;
                      box-shadow:0 4px 24px -8px rgba(10,34,64,0.10), 0 1px 0 rgba(10,34,64,0.04);">

          <!-- Top electric accent line -->
          <tr>
            <td style="background:linear-gradient(90deg,#2D7DFF 0%,#6BA8FF 100%);
                        height:3px; border-radius:16px 16px 0 0; font-size:0; line-height:0;">&nbsp;</td>
          </tr>

          <!-- ── HEADER ── -->
          <tr>
            <td class="header-pad" align="left"
                style="padding:32px 40px 0 40px;">
              <!-- Logo -->
              <a href="https://agentdna.io" target="_blank" rel="noopener noreferrer"
                 style="display:inline-block; text-decoration:none;">
                <img class="logo-img"
                     src="https://agentdna.io/assets/wb-BuhqEaFf.png"
                     alt="AgentDNA"
                     height="36"
                     style="height:36px; width:auto; display:block;" />
              </a>
            </td>
          </tr>

          <!-- ── BODY ── -->
          <tr>
            <td class="body-pad" style="padding:32px 40px 40px 40px;">

              <!-- Eyebrow pill -->
              <table role="presentation" cellpadding="0" cellspacing="0" border="0"
                     style="margin-bottom:20px;">
                <tr>
                  <td style="background-color:#EAF2FF; border-radius:999px;
                              padding:5px 12px;">
                    <p style="margin:0; font-size:11px; font-weight:600; color:#1D5FD9;
                               text-transform:uppercase; letter-spacing:0.14em;
                               font-family:'Inter',-apple-system,sans-serif; line-height:1;">
                      &#9679;&ensp;Private Beta ·
                    </p>
                  </td>
                </tr>
              </table>

              <!-- Headline -->
              <h1 class="h1"
                  style="margin:0 0 10px; font-size:30px; font-weight:800; line-height:1.15;
                         color:#0A2240; letter-spacing:-0.025em;
                         font-family:'Inter',-apple-system,sans-serif;">
                You're in.
              </h1>
           

              <!-- Greeting / body copy -->
              <p style="margin:0 0 16px; font-size:15.5px; color:#0E1A2B; line-height:1.7;
                         font-family:'Inter',-apple-system,sans-serif;">
                Hi {{.Name}},
              </p>
              <p style="margin:0 0 16px; font-size:15.5px; color:#0E1A2B; line-height:1.7;
                         font-family:'Inter',-apple-system,sans-serif;">
                Thank you for registering for the <strong style="color:#0A2240;">AgentDNA
                private beta</strong>.
              </p>
              <p style="margin:0 0 28px; font-size:15.5px; color:#0E1A2B; line-height:1.7;
                         font-family:'Inter',-apple-system,sans-serif;">
                Below is your unique private access key. Use it to activate your beta account.
              </p>

              <!-- ── KEY BOX ── -->
              <table class="key-pad" role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"
                     style="background-color:#F6F9FE; border:1.5px solid #DCE6F4;
                            border-radius:12px; margin-bottom:28px;">
                <tr>
                  <td style="padding:22px 26px;">

                    <!-- Label row + copy button -->
                    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"
                           style="margin-bottom:8px;">
                      <tr>
                        <td valign="middle">
                          <p style="margin:0; font-size:11px; font-weight:600; color:#1D5FD9;
                                     text-transform:uppercase; letter-spacing:0.14em;
                                     font-family:'Inter',-apple-system,sans-serif; line-height:1;">
                            Your Private Beta Key
                          </p>
                        </td>
                      </tr>
                    </table>

                    <!-- Key value -->
                    <p id="betaKey" class="key-mono"
                       style="margin:0 0 16px; font-size:14.5px; font-weight:500;
                              color:#0A2240; line-height:1.7; word-break:break-all;
                              font-family:'JetBrains Mono','Courier New',Courier,monospace;
                              letter-spacing:1.5px; background:#ffffff;
                              border:1px solid #DCE6F4; border-radius:8px;
                              padding:12px 14px;">
                      {{.APIKey}}
                    </p>


                  </td>
                </tr>
              </table>

              <!-- ── USAGE CONTEXT ── -->
              <p style="margin:24px 0 8px; font-size:15.5px; color:#0E1A2B; line-height:1.7;
                         font-family:'Inter',-apple-system,sans-serif;">
                Use this key when initialising AgentDNA inside your agent code.
              </p>
              <p style="margin:0 0 20px; font-size:15.5px; color:#0E1A2B; line-height:1.7;
                         font-family:'Inter',-apple-system,sans-serif;">
                To help you get started quickly, we've put together a step-by-step onboarding
                guide covering <strong style="color:#0A2240;">installation</strong> and
                <strong style="color:#0A2240;">initialisation</strong>.
              </p>

              <!-- ── GUIDE BUTTON ── -->
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"
                     style="margin-bottom:28px;">
                <tr>
                  <td align="center">
                    <a href="https://hub.agentdna.io/tutorials"
                       target="_blank" rel="noopener noreferrer"
                       style="display:inline-block; background-color:#2D7DFF;
                              color:#ffffff; text-decoration:none;
                              font-size:14.5px; font-weight:600; letter-spacing:0.01em;
                              padding:13px 32px; border-radius:999px;
                              font-family:'Inter',-apple-system,sans-serif;
                              box-shadow:0 8px 24px -8px rgba(45,125,255,0.55);">
                      Quick Guide &amp; Tutorials &rarr;
                    </a>
                  </td>
                </tr>
              </table>


              <!-- Divider -->
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"
                     style="margin-bottom:28px;">
                <tr>
                  <td style="border-top:1px solid #EDF3FB; font-size:0; line-height:0;">&nbsp;</td>
                </tr>
              </table>

              <!-- Sign-off -->
              <p style="margin:0 0 4px; font-size:15.5px; color:#0E1A2B; line-height:1.7;
                         font-family:'Inter',-apple-system,sans-serif;">
                We can't wait to see what you build.
              </p>
              <p style="margin:0 0 2px; font-size:15.5px; color:#475569; line-height:1.7;
                         font-family:'Inter',-apple-system,sans-serif;">
                Thanks &amp; regards,
              </p>
              <p style="margin:0; font-size:15.5px; font-weight:700; color:#0A2240; line-height:1.7;
                         font-family:'Inter',-apple-system,sans-serif;">
                The AgentDNA Team
              </p>

            </td>
          </tr>

          <!-- ── FOOTER ── -->
          <tr>
            <td class="footer-pad"
                style="background-color:#F6F9FE; border-top:1px solid #EDF3FB;
                       padding:22px 40px; border-radius:0 0 16px 16px;">

              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
                <tr>
                  <td style="border-top:1px solid #EDF3FB; padding-top:16px;">
                    <p style="margin:0; font-size:11.5px; color:#94A3B8; text-align:center;
                               line-height:1.6; font-family:'Inter',-apple-system,sans-serif;">
                      You received this because you signed up for the AgentDNA private beta.
                    </p>
                    <p style="margin:6px 0 0; font-size:11.5px; color:#94A3B8; text-align:center;
                               line-height:1.6; font-family:'Inter',-apple-system,sans-serif;">
                      &copy; 2026 AgentDNA, Inc. &nbsp;&bull;&nbsp;
                      <a href="https://agentdna.io" style="color:#2D7DFF; text-decoration:none;">agentdna.io</a>
                      &nbsp;&bull;&nbsp;
                    </p>
                  </td>
                </tr>
              </table>

            </td>
          </tr>

        </table>
        <!-- /Email card -->

      </td>
    </tr>
  </table>
</body>
</html>
`))

// OTPVerification sends a 6-digit OTP code to the given email for registration verification.
func OTPVerification(toEmail, code string) (Message, error) {
	data := struct {
		Email string
		Code  string
		Year  int
	}{
		Email: toEmail,
		Code:  code,
		Year:  time.Now().Year(),
	}
	html, err := render(otpVerificationTmpl, data)
	if err != nil {
		return Message{}, err
	}
	return Message{
		To:      toEmail,
		Subject: "Your AgentDNA verification code",
		HTML:    html,
	}, nil
}

var otpVerificationTmpl = template.Must(template.New("otp-verification").Parse(`
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1.0"/>
  <title>Verify your email · AgentDNA</title>
  <style>body{margin:0;padding:0;background:#F0F4F9;font-family:'Inter',-apple-system,sans-serif;}</style>
</head>
<body>
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#F0F4F9;padding:40px 16px;">
    <tr><td align="center" valign="top">
      <table role="presentation" width="580" cellpadding="0" cellspacing="0" border="0"
             style="max-width:580px;width:100%;background:#fff;border-radius:16px;border:1px solid #DCE6F4;box-shadow:0 4px 24px -8px rgba(10,34,64,.10);">
        <tr><td style="background:linear-gradient(90deg,#2D7DFF 0%,#6BA8FF 100%);height:3px;border-radius:16px 16px 0 0;font-size:0;line-height:0;">&nbsp;</td></tr>
        <tr><td style="padding:32px 40px 0;">
          <a href="https://agentdna.io" style="display:inline-block;text-decoration:none;">
            <img src="https://agentdna.io/assets/wb-BuhqEaFf.png" alt="AgentDNA" height="36" style="height:36px;width:auto;display:block;"/>
          </a>
        </td></tr>
        <tr><td style="padding:32px 40px 40px;">
          <table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin-bottom:20px;">
            <tr><td style="background:#EAF2FF;border-radius:999px;padding:5px 12px;">
              <p style="margin:0;font-size:11px;font-weight:600;color:#1D5FD9;text-transform:uppercase;letter-spacing:.14em;line-height:1;">&#9679;&ensp;Email Verification</p>
            </td></tr>
          </table>
          <h1 style="margin:0 0 10px;font-size:28px;font-weight:800;color:#0A2240;">Verify your email address</h1>
          <p style="margin:0 0 24px;font-size:15.5px;color:#0E1A2B;line-height:1.7;">
            Use the code below to complete your registration. It expires in <strong>5 minutes</strong>.
          </p>
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-bottom:28px;">
            <tr><td align="center" style="background:#F6F9FE;border:1.5px solid #DCE6F4;border-radius:12px;padding:28px 20px;">
              <p style="margin:0;font-size:42px;font-weight:800;letter-spacing:12px;color:#0A2240;font-family:'Courier New',monospace;">{{.Code}}</p>
            </td></tr>
          </table>
          <p style="margin:0;font-size:13px;color:#94A3B8;">If you did not request this, you can safely ignore this email.</p>
        </td></tr>
        <tr><td style="background:#F6F9FE;border-top:1px solid #EDF3FB;padding:20px 40px;border-radius:0 0 16px 16px;">
          <p style="margin:0;font-size:11.5px;color:#94A3B8;text-align:center;">&copy; {{.Year}} AgentDNA, Inc.</p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>
`))
