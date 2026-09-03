package zmate

import (
	"os"
	"path/filepath"
	"testing"

	sshcrypto "golang.org/x/crypto/ssh"
)

func TestParseListenAddress(t *testing.T) {
	tests := []struct {
		name, address, host string
		port                int
		wantErr             bool
	}{
		{name: "IPv4", address: "127.0.0.1:2222", host: "127.0.0.1", port: 2222},
		{name: "all interfaces", address: ":2222", host: "", port: 2222},
		{name: "IPv6", address: "[::1]:2222", host: "::1", port: 2222},
		{name: "missing port", address: "localhost", wantErr: true},
		{name: "invalid port", address: "localhost:nope", wantErr: true},
		{name: "out of range", address: "localhost:65536", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			host, port, err := parseListenAddress(test.address)
			if test.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("parseListenAddress() error = %v", err)
			}
			if host != test.host || port != test.port {
				t.Fatalf("parseListenAddress() = %q, %d; want %q, %d", host, port, test.host, test.port)
			}
		})
	}
}

func TestLoadOrCreateHostKeyPersistsKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys", "host_key")
	first, returnedPath, err := loadOrCreateHostKey(path)
	if err != nil {
		t.Fatalf("loadOrCreateHostKey() error = %v", err)
	}
	if returnedPath != path {
		t.Fatalf("path = %q; want %q", returnedPath, path)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat host key: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("host key permissions = %o; want 600", info.Mode().Perm())
	}

	second, _, err := loadOrCreateHostKey(path)
	if err != nil {
		t.Fatalf("reload host key: %v", err)
	}
	firstFingerprint := sshcrypto.FingerprintSHA256(first.PublicKey())
	secondFingerprint := sshcrypto.FingerprintSHA256(second.PublicKey())
	if firstFingerprint != secondFingerprint {
		t.Fatalf("host key changed: %s != %s", firstFingerprint, secondFingerprint)
	}
}

func TestHostKeyAliasIsStableAndKeySpecific(t *testing.T) {
	first, _, err := loadOrCreateHostKey(filepath.Join(t.TempDir(), "first"))
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := loadOrCreateHostKey(filepath.Join(t.TempDir(), "second"))
	if err != nil {
		t.Fatal(err)
	}
	if hostKeyAlias(first) != hostKeyAlias(first) {
		t.Fatal("alias is not stable")
	}
	if hostKeyAlias(first) == hostKeyAlias(second) {
		t.Fatal("different keys received the same alias")
	}
}

func TestSSHConnectionCommandUsesIsolatedHostIdentity(t *testing.T) {
	command := sshConnectionCommand(43210, "token", "relay.example", "zmate-abc123")
	want := "ssh -oHostKeyAlias=zmate-abc123 -p43210 token@relay.example"
	if command != want {
		t.Fatalf("sshConnectionCommand() = %q; want %q", command, want)
	}
}
