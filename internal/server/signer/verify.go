package signer

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// VerifyDigestMode 验证 signtool /ds + /csp 组合是否可用
// 使用一个测试 stub PE 验证 /dg → /ds 流程
func (s *Signer) VerifyDigestMode(ctx context.Context) bool {
	tmpDir, err := os.MkdirTemp(s.cfg.TempDir, "codesign-verify-")
	if err != nil {
		fmt.Printf("create temp dir failed: %v\n", err)
		return false
	}
	defer os.RemoveAll(tmpDir)

	// 准备一个简单的测试文件
	testFile := filepath.Join(tmpDir, "test.exe")
	minPE := buildMinimalPE()
	if err := os.WriteFile(testFile, minPE, 0600); err != nil {
		fmt.Printf("write stub PE failed: %v\n", err)
		return false
	}

	timeout := time.Duration(s.cfg.SignTimeout) * time.Second

	// Step 1: signtool /dg 生成 .dig + .p7u
	dgCtx, dgCancel := context.WithTimeout(ctx, timeout)
	defer dgCancel()

	dgArgs := []string{
		"sign", "/dg", tmpDir,
		"/fd", "sha256",
		"/f", s.cfg.CertPath,
		testFile,
	}
	dgCmd := exec.CommandContext(dgCtx, s.cfg.SigntoolPath, dgArgs...)
	if out, err := dgCmd.CombinedOutput(); err != nil {
		fmt.Printf("signtool /dg failed: %v\n%s\n", err, out)
		return false
	}

	// Step 2: signtool /ds 签名 digest（关键测试步骤）
	digPath := testFile + ".dig"
	dsCtx, dsCancel := context.WithTimeout(ctx, timeout)
	defer dsCancel()

	dsArgs := []string{
		"sign", "/ds",
		"/f", s.cfg.CertPath,
		"/csp", s.cfg.CSPName,
		"/k", s.cfg.CSPKey,
		"/fd", "sha256",
		digPath,
	}
	dsCmd := exec.CommandContext(dsCtx, s.cfg.SigntoolPath, dsArgs...)
	if out, err := dsCmd.CombinedOutput(); err != nil {
		fmt.Printf("signtool /ds failed: %v\n%s\n", err, out)
		return false
	}

	fmt.Println("signtool /ds + /csp test: OK")
	return true
}

// buildMinimalPE 构建最小的合法 PE 二进制（仅用于测试）
func buildMinimalPE() []byte {
	buf := make([]byte, 512)

	// DOS header
	buf[0] = 'M'
	buf[1] = 'Z'
	// e_lfanew = 0x40
	binary.LittleEndian.PutUint32(buf[0x3C:], 0x40)

	// PE signature
	buf[0x40] = 'P'
	buf[0x41] = 'E'
	buf[0x42] = 0
	buf[0x43] = 0

	// COFF header: Machine = x86-64
	binary.LittleEndian.PutUint16(buf[0x44:], 0x8664)
	// NumberOfSections = 0
	binary.LittleEndian.PutUint16(buf[0x46:], 0)
	// SizeOfOptionalHeader = 240
	binary.LittleEndian.PutUint16(buf[0x54:], 240)
	// Characteristics
	binary.LittleEndian.PutUint16(buf[0x56:], 0x2102)

	// Optional header: Magic = PE32+ (0x020B)
	binary.LittleEndian.PutUint16(buf[0x58:], 0x020B)

	return buf
}
