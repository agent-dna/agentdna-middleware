package handler

import (
	"fmt"
	"net/url"
	"strings"
)

// joinURL appends path elements to a service base URL with url.JoinPath, so a
// base given with or without a trailing slash yields the same URL and no "//"
// or missing "/" can creep in.
//
// The base must be an absolute http(s) URL. An empty value, or one that kept
// its quotes from an env file ("\"https://...\""), is reported here rather
// than surfacing later as "unsupported protocol scheme" from the HTTP client.
func joinURL(base string, elem ...string) (string, error) {
	base = strings.TrimSpace(base)
	u, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("invalid service URL %q: %v", base, err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", fmt.Errorf("invalid service URL %q: want http(s)://host[/path]", base)
	}
	return u.JoinPath(elem...).String(), nil
}

// CheckServiceURL reports whether a configured service base URL is usable,
// for a startup warning. An empty value is not an error here: some services
// are optional, and the endpoints that need them fail with their own message.
func CheckServiceURL(name, raw string) error {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	if _, err := joinURL(raw); err != nil {
		return fmt.Errorf("%s: %v", name, err)
	}
	return nil
}

// agentServiceURL builds a URL on the agent admin service from base
// (CREATE_AGENT_ENDPOINT / UPDATE_AGENT_ENDPOINT), falling back to
// ADMIN_SERVICE_URL when base is not set.
func (h *Handler) agentServiceURL(base, envName string, elem ...string) (string, error) {
	if strings.TrimSpace(base) == "" {
		base = h.adminServiceURL
	}
	if strings.TrimSpace(base) == "" {
		return "", fmt.Errorf("%s and ADMIN_SERVICE_URL are both unset", envName)
	}
	return joinURL(base, elem...)
}
