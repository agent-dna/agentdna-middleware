package handler

import "testing"

func TestJoinURL(t *testing.T) {
	cases := []struct {
		base string
		elem []string
		want string
	}{
		{"https://admin.example.io", []string{"agent-admin", "v1", "create-agent"}, "https://admin.example.io/agent-admin/v1/create-agent"},
		{"https://admin.example.io/", []string{"agent-admin", "v1", "create-agent"}, "https://admin.example.io/agent-admin/v1/create-agent"},
		{"  https://admin.example.io//  ", []string{"agent-admin/v1/login"}, "https://admin.example.io/agent-admin/v1/login"},
		{"https://cbac.example.io/cbac/v1", []string{"lhi-scores"}, "https://cbac.example.io/cbac/v1/lhi-scores"},
		{"http://localhost:8000/", []string{"decisions", "by-hash", "abc123"}, "http://localhost:8000/decisions/by-hash/abc123"},
	}
	for _, c := range cases {
		got, err := joinURL(c.base, c.elem...)
		if err != nil || got != c.want {
			t.Errorf("joinURL(%q, %v): want %q, got %q (err %v)", c.base, c.elem, c.want, got, err)
		}
	}

	for _, bad := range []string{"", `"https://admin.example.io"`, "admin.example.io", "agent-admin/v1"} {
		if _, err := joinURL(bad, "x"); err == nil {
			t.Errorf("joinURL(%q): want an error", bad)
		}
	}
}

func TestAgentServiceURL(t *testing.T) {
	h := &Handler{adminServiceURL: "http://admin:8000/"}
	cases := []struct{ base, want string }{
		{"http://create:8000/", "http://create:8000/agent-admin/v1/create-agent"},
		{"http://create:8000", "http://create:8000/agent-admin/v1/create-agent"},
		{"", "http://admin:8000/agent-admin/v1/create-agent"},
	}
	for _, c := range cases {
		got, err := h.agentServiceURL(c.base, "CREATE_AGENT_ENDPOINT", "agent-admin", "v1", "create-agent")
		if err != nil || got != c.want {
			t.Errorf("base %q: want %q, got %q (err %v)", c.base, c.want, got, err)
		}
	}

	if _, err := (&Handler{}).agentServiceURL("", "CREATE_AGENT_ENDPOINT", "x"); err == nil {
		t.Error("want an error when neither the endpoint nor ADMIN_SERVICE_URL is set")
	}
}
