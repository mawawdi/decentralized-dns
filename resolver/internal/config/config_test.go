package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFromEnvDefaults(t *testing.T) {
	cfg, err := FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RPCURL != "http://127.0.0.1:8545" {
		t.Errorf("RPCURL default = %q", cfg.RPCURL)
	}
	if cfg.RESTPort != 8080 || cfg.UDPPort != 5354 || cfg.BTListenPort != 42069 {
		t.Errorf("port defaults = %d/%d/%d", cfg.RESTPort, cfg.UDPPort, cfg.BTListenPort)
	}
	if cfg.CacheSize != 4096 {
		t.Errorf("CacheSize default = %d", cfg.CacheSize)
	}
}

func TestFromEnvOverridesAndErrors(t *testing.T) {
	t.Setenv("REST_PORT", "9090")
	t.Setenv("CONTRACT_ADDRESS", "0xabc")
	cfg, err := FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RESTPort != 9090 {
		t.Errorf("RESTPort = %d, want 9090", cfg.RESTPort)
	}
	if cfg.ContractAddress != "0xabc" {
		t.Errorf("ContractAddress = %q", cfg.ContractAddress)
	}

	t.Setenv("UDP_PORT", "not-a-number")
	if _, err := FromEnv(); err == nil {
		t.Error("expected error for non-integer UDP_PORT")
	}
}

func TestFromEnvBoolFlags(t *testing.T) {
	cfg, err := FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AllowPeerHints || cfg.EnforceType {
		t.Errorf("bool flags should default to false: peerHints=%v enforceType=%v", cfg.AllowPeerHints, cfg.EnforceType)
	}

	t.Setenv("ENFORCE_CONTENT_TYPE", "true")
	t.Setenv("ALLOW_PEER_HINTS", "1")
	cfg, err = FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.EnforceType || !cfg.AllowPeerHints {
		t.Errorf("bool flags not parsed: peerHints=%v enforceType=%v", cfg.AllowPeerHints, cfg.EnforceType)
	}
}

func TestLoadDotEnv(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	contents := "# a comment\nexport DDNS_TEST_FOO=bar\nDDNS_TEST_QUOTED=\"baz\"\n\nDDNS_TEST_PRESET=fromfile\n"
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"DDNS_TEST_FOO", "DDNS_TEST_QUOTED"} {
		os.Unsetenv(k)
		t.Cleanup(func() { os.Unsetenv(k) })
	}
	// A real env var must win over the file.
	t.Setenv("DDNS_TEST_PRESET", "fromenv")

	loadDotEnv(path)

	if got := os.Getenv("DDNS_TEST_FOO"); got != "bar" {
		t.Errorf("FOO = %q, want bar", got)
	}
	if got := os.Getenv("DDNS_TEST_QUOTED"); got != "baz" {
		t.Errorf("QUOTED = %q, want baz (quotes stripped)", got)
	}
	if got := os.Getenv("DDNS_TEST_PRESET"); got != "fromenv" {
		t.Errorf("PRESET = %q, want fromenv (real env must win)", got)
	}
	// A missing file is a silent no-op.
	loadDotEnv(filepath.Join(t.TempDir(), "absent.env"))
}

func TestLoadDeployments(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "localhost.json")
	doc := `{"contracts":{"NamespaceDApp":"0xNS","RecordSchemaRegistry":"0xREG","ResolverRegistry":"0xRESREG","ResolverIncentives":"0xRESINC","ZKVerifier":"0xZK"}}`
	if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	ns, reg, resReg, resInc := loadDeployments(path)
	if ns != "0xNS" || reg != "0xREG" || resReg != "0xRESREG" || resInc != "0xRESINC" {
		t.Errorf("loadDeployments = %q,%q,%q,%q want 0xNS,0xREG,0xRESREG,0xRESINC", ns, reg, resReg, resInc)
	}
	if ns, reg, resReg, resInc := loadDeployments(filepath.Join(dir, "missing.json")); ns != "" || reg != "" || resReg != "" || resInc != "" {
		t.Errorf("missing file should yield empty, got %q,%q,%q,%q", ns, reg, resReg, resInc)
	}
}
