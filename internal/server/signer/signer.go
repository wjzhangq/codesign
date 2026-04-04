package signer

import (
	"context"
	"path/filepath"
	"regexp"

	"codesign/internal/server/config"
)

var safeFilename = regexp.MustCompile(`[^a-zA-Z0-9._-]`)

// Signer 封装 signtool 调用，保证 eToken 硬件签名串行执行
type Signer struct {
	cfg    *config.Config
	lockCh chan struct{} // 用于 ctx 感知的锁等待（容量 1 的 channel 充当互斥锁）
}

// New 创建 Signer
func New(cfg *config.Config) *Signer {
	s := &Signer{
		cfg:    cfg,
		lockCh: make(chan struct{}, 1),
	}
	// 初始时槽位可用（表示锁未被持有）
	s.lockCh <- struct{}{}
	return s
}

// withLock 在互斥锁保护下执行 fn，等待期间响应 ctx 取消
func (s *Signer) withLock(ctx context.Context, fn func() error) error {
	// 先检查 ctx 是否已超时
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// 使用 channel 实现可取消的锁等待
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.lockCh:
		// 获取令牌（相当于持有锁）
	}
	defer func() { s.lockCh <- struct{}{} }() // 释放令牌

	// 锁已获取，再次检查 ctx
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
