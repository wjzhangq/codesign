package signer

import (
	"context"
	"path/filepath"
	"regexp"
	"sync"

	"codesign/internal/server/config"
)

var safeFilename = regexp.MustCompile(`[^a-zA-Z0-9._-]`)

// Signer 封装 signtool 调用，保证 eToken 硬件签名串行执行
type Signer struct {
	cfg *config.Config
	mu  sync.Mutex // eToken 硬件签名只能串行
}

// New 创建 Signer
func New(cfg *config.Config) *Signer {
	return &Signer{cfg: cfg}
}

// withLock 在互斥锁保护下执行 fn，先检查 ctx 是否超时
func (s *Signer) withLock(ctx context.Context, fn func() error) error {
	// 检查 ctx 是否已超时
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// 锁获取后再次检查 ctx
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	return fn()
}

// sanitize 清理文件名，只保留安全字符
func sanitize(name string) string {
	base := filepath.Base(name)
	safe := safeFilename.ReplaceAllString(base, "_")
	if len(safe) > 255 {
		safe = safe[:255]
	}
	if safe == "" || safe == "." || safe == ".." {
		safe = "file"
	}
	return safe
}
