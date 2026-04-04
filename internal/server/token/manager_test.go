package token

import (
	"os"
	"strings"
	"testing"
)

func TestTokenCreateAndVerify(t *testing.T) {
	// 创建临时 token db
	f, err := os.CreateTemp("", "tokens-*.json")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	defer os.Remove(f.Name())

	secret := "test-secret-at-least-32-characters-long"
	tm, err := NewManager(secret, f.Name())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	// 创建 token
	tok, err := tm.Create("testuser")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// 验证 token 格式 (3 parts separated by ".")
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Errorf("token has %d parts, want 3", len(parts))
	}

	// 验证 token
	user, err := tm.Verify(tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if user != "testuser" {
		t.Errorf("user: got %q, want %q", user, "testuser")
	}
}

func TestTokenRevoke(t *testing.T) {
	f, _ := os.CreateTemp("", "tokens-*.json")
	f.Close()
	defer os.Remove(f.Name())

	tm, _ := NewManager("test-secret-at-least-32-characters-long", f.Name())

	tok, _ := tm.Create("revokeuser")

	// 撤销前应能验证
	if _, err := tm.Verify(tok); err != nil {
		t.Fatalf("Verify before revoke: %v", err)
	}

	// 撤销
	if err := tm.Revoke("revokeuser"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	// 撤销后应拒绝
	_, err := tm.Verify(tok)
	if err == nil {
		t.Error("expected error after revoke, got nil")
	}
}

func TestTokenInvalidSignature(t *testing.T) {
	f, _ := os.CreateTemp("", "tokens-*.json")
	f.Close()
	defer os.Remove(f.Name())

	tm, _ := NewManager("test-secret-at-least-32-characters-long", f.Name())

	_, err := tm.Verify("invalid.token.here")
	if err == nil {
		t.Error("expected error for invalid token")
	}
}

func TestTokenPersistence(t *testing.T) {
	f, _ := os.CreateTemp("", "tokens-*.json")
	f.Close()
	defer os.Remove(f.Name())

	secret := "test-secret-at-least-32-characters-long"
	tm1, _ := NewManager(secret, f.Name())
	tok, _ := tm1.Create("persistuser")

	// 重新加载 manager
	tm2, err := NewManager(secret, f.Name())
	if err != nil {
		t.Fatalf("reload manager: %v", err)
	}

	// 应能用新 manager 验证 token
	user, err := tm2.Verify(tok)
	if err != nil {
		t.Fatalf("Verify after reload: %v", err)
	}
	if user != "persistuser" {
		t.Errorf("user: got %q, want %q", user, "persistuser")
	}
}
