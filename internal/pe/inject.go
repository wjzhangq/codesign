package pe

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// InjectSignature 将签名注入 PE 文件
// 流程:
//  1. 截断旧签名（如有 CertTableOffset > 0）
//  2. 追加 certTable 到文件末尾
//  3. 更新 Security Dir Entry (VA + Size)
//  4. 重新计算并写入 CheckSum
//  5. 原子替换（write tmp → rename）
func InjectSignature(filePath string, info *PEInfo, certTable []byte) error {
	tmpPath := filePath + ".codesign.tmp"

	// 1. 将原文件复制到临时文件
	if err := copyFile(filePath, tmpPath); err != nil {
		return fmt.Errorf("copy to tmp: %w", err)
	}

	// 发生错误时清理临时文件
	success := false
	defer func() {
		if !success {
			os.Remove(tmpPath) // nolint: 清理临时文件，失败无需处理
		}
	}()

	f, err := os.OpenFile(tmpPath, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open tmp: %w", err)
	}

	// 2. 确定写入位置 — 截断旧签名
	var writeOff int64
	if info.CertTableOffset > 0 {
		// 截断到 CertTableOffset（移除旧签名）
		if err := f.Truncate(int64(info.CertTableOffset)); err != nil {
			f.Close()
			return fmt.Errorf("truncate old signature: %w", err)
		}
		writeOff = int64(info.CertTableOffset)
	} else {
		// 无签名，追加到文件末尾
		stat, err := f.Stat()
		if err != nil {
			f.Close()
			return fmt.Errorf("stat tmp: %w", err)
		}
		writeOff = stat.Size()
	}

	// 3. 追加 Certificate Table
	if _, err := f.WriteAt(certTable, writeOff); err != nil {
		f.Close()
		return fmt.Errorf("write certificate table: %w", err)
	}

	// 4. 更新 Security Dir Entry (VA=writeOff, Size=len(certTable))
	var sd [8]byte
	binary.LittleEndian.PutUint32(sd[0:4], uint32(writeOff))
	binary.LittleEndian.PutUint32(sd[4:8], uint32(len(certTable)))
	if _, err := f.WriteAt(sd[:], int64(info.SecurityDirOffset)); err != nil {
		f.Close()
		return fmt.Errorf("update security directory: %w", err)
	}

	// 5. 重新计算 CheckSum
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		f.Close()
		return err
	}
	cs := ComputePEChecksum(f, info.ChecksumOffset)
	var csBuf [4]byte
	binary.LittleEndian.PutUint32(csBuf[:], cs)
	if _, err := f.WriteAt(csBuf[:], int64(info.ChecksumOffset)); err != nil {
		f.Close()
		return fmt.Errorf("update checksum: %w", err)
	}

	if err := f.Close(); err != nil {
		return fmt.Errorf("close tmp: %w", err)
	}

	// 6. 原子替换
	if err := os.Rename(tmpPath, filePath); err != nil {
		return fmt.Errorf("rename tmp to target: %w", err)
	}

	success = true
	return nil
}

// copyFile 复制文件
func copyFile(src, dst string) error {
	sf, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sf.Close()

	df, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer df.Close()

	if _, err := io.Copy(df, sf); err != nil {
		return err
	}

	return df.Sync()
}
