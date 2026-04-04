package pe

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
)

// ComputeAuthenticodeDigest 计算 PE 文件的 Authenticode SHA-256 摘要
// 跳过三个区域:
//  1. CheckSum (4 bytes)
//  2. Security Directory Entry (8 bytes)
//  3. Certificate Table (全部)
func ComputeAuthenticodeDigest(path string, info *PEInfo) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}
	defer f.Close()

	return computeDigest(f, info)
}

// ComputeAuthenticodeDigestFromReader 从 io.ReadSeeker 计算 Authenticode 摘要
func ComputeAuthenticodeDigestFromReader(r io.ReadSeeker, info *PEInfo) ([]byte, error) {
	return computeDigest(r, info)
}

func computeDigest(r io.ReadSeeker, info *PEInfo) ([]byte, error) {
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}

	h := sha256.New()

	// 区段 1: [0, ChecksumOffset)
	if err := copyN(h, r, int64(info.ChecksumOffset)); err != nil {
		return nil, fmt.Errorf("hash before checksum: %w", err)
	}

	// 跳过 CheckSum (4 bytes)
	if _, err := r.Seek(int64(info.ChecksumOffset)+4, io.SeekStart); err != nil {
		return nil, err
	}

	// 区段 2: [ChecksumOffset+4, SecurityDirOffset)
	seg2Len := int64(info.SecurityDirOffset) - int64(info.ChecksumOffset) - 4
	if seg2Len > 0 {
		if err := copyN(h, r, seg2Len); err != nil {
			return nil, fmt.Errorf("hash between checksum and security dir: %w", err)
		}
	}

	// 跳过 Security Directory Entry (8 bytes)
	if _, err := r.Seek(int64(info.SecurityDirOffset)+8, io.SeekStart); err != nil {
		return nil, err
	}

	// 区段 3: [SecurityDirOffset+8, CertTableOffset or EOF)
	var end int64
	if info.CertTableOffset > 0 {
		end = int64(info.CertTableOffset)
	} else {
		end = info.FileSize
	}

	seg3Start := int64(info.SecurityDirOffset) + 8
	seg3Len := end - seg3Start
	if seg3Len > 0 {
		if err := copyN(h, r, seg3Len); err != nil {
			return nil, fmt.Errorf("hash main body: %w", err)
		}
	}

	// Certificate Table 完全跳过（不参与 hash）

	return h.Sum(nil), nil
}

// copyN 将 n 字节从 r 拷贝到 w，严格检查字节数
func copyN(w io.Writer, r io.Reader, n int64) error {
	if n <= 0 {
		return nil
	}
	written, err := io.CopyN(w, r, n)
	if err != nil {
		return err
	}
	if written != n {
		return fmt.Errorf("expected to copy %d bytes, got %d", n, written)
	}
	return nil
}
