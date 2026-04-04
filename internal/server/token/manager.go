package token

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// TokenInfo token 信息
type TokenInfo struct {
	User      string    `json:"user"`
	CreatedAt time.Time `json:"created_at"`
	Revoked   bool      `json:"revoked"`
}

// tokenDB 持久化格式
type tokenDB struct {
	Users map[string]*TokenInfo `json:"users"`
}

// Manager JWT token 管理器
type Manager struct {
	mu     sync.RWMutex
	secret []byte
	dbPath string
	db     *tokenDB
}

// NewManager 创建 TokenManager
func NewManager(secret, dbPath string) (*Manager, error) {
	m := &Manager{
		secret: []byte(secret),
		dbPath: dbPath,
		db:     &tokenDB{Users: make(map[string]*TokenInfo)},
	}
	// 尝试加载已有的 token 数据库
	if err := m.load(); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("load token db: %w", err)
	}
	return m, nil
}

// Create 为用户创建 token（永不过期）
func (m *Manager) Create(user string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	header := base64URLEncode([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := base64URLEncode(mustJSON(map[string]any{
		"sub": user,
		"iat": time.Now().Unix(),
	}))
	msg := header + "." + payload
	sig := base64URLEncode(hmacSHA256(m.secret, []byte(msg)))
	token := msg + "." + sig

	// 记录到数据库
	m.db.Users[user] = &TokenInfo{
		User:      user,
		CreatedAt: time.Now(),
		Revoked:   false,
	}
	if err := m.save(); err != nil {
		return "", fmt.Errorf("save token db: %w", err)
	}

	return token, nil
}

// Verify 验证 token，返回 user
func (m *Manager) Verify(token string) (string, error) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return "", fmt.Errorf("malformed token")
	}

	msg := parts[0] + "." + parts[1]
	expectedSig := base64URLEncode(hmacSHA256(m.secret, []byte(msg)))
	if !hmac.Equal([]byte(parts[2]), []byte(expectedSig)) {
		return "", fmt.Errorf("invalid signature")
	}

	// 解析 payload
	payloadBytes, err := base64URLDecode(parts[1])
	if err != nil {
		return "", fmt.Errorf("decode payload: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return "", fmt.Errorf("parse payload: %w", err)
	}
	user, _ := claims["sub"].(string)
	if user == "" {
		return "", fmt.Errorf("missing sub claim")
	}

	// 检查 revoke 状态
	m.mu.RLock()
	defer m.mu.RUnlock()

	info, ok := m.db.Users[user]
	if !ok {
		return "", fmt.Errorf("unknown user %q", user)
	}
	if info.Revoked {
		return "", fmt.Errorf("token for user %q has been revoked", user)
	}

	return user, nil
}

// Revoke 撤销某用户的 token
func (m *Manager) Revoke(user string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	info, ok := m.db.Users[user]
	if !ok {
		return fmt.Errorf("user %q not found", user)
	}
	info.Revoked = true
	return m.save()
}

// List 列出所有 token 信息
func (m *Manager) List() []*TokenInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*TokenInfo, 0, len(m.db.Users))
	for _, info := range m.db.Users {
		result = append(result, info)
	}
	return result
}

// load 从文件加载 token 数据库
func (m *Manager) load() error {
	data, err := os.ReadFile(m.dbPath)
	if err != nil {
		return err
	}
	// 空文件视为空数据库
	if len(data) == 0 {
		return nil
	}
	return json.Unmarshal(data, m.db)
}

// save 保存 token 数据库到文件（调用方须持有锁）
func (m *Manager) save() error {
	data, err := json.MarshalIndent(m.db, "", "  ")
	if err != nil {
		return err
	}
	// 原子写入
	tmpPath := m.dbPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmpPath, m.dbPath)
}

// --- 辅助函数 ---

func hmacSHA256(key, msg []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	return mac.Sum(nil)
}

func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func base64URLDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func mustJSON(v any) []byte {
	data, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("json marshal: %v", err))
	}
	return data
}
