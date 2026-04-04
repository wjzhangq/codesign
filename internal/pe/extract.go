package pe

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// ExtractSignatureData 从已签名 PE 文件提取签名相关数据
// 返回: certTable 字节, checksum, secDirVA, secDirSize
func ExtractSignatureData(filePath string) (certTable []byte, checksum uint32, va uint32, size uint32, err error) {
	info, err := ParsePE(filePath)
	if err != nil {
		return nil, 0, 0, 0, fmt.Errorf("parse PE: %w", err)
	}

	if info.CertTableOffset == 0 || info.CertTableSize == 0 {
		return nil, 0, 0, 0, fmt.Errorf("file has no signature (CertTableOffset=0)")
	}

	f, err := os.Open(filePath)
	if err != nil {
		return nil, 0, 0, 0, fmt.Errorf("open file: %w", err)
	}
	defer f.Close()

	// 读取 Certificate Table
	certTable = make([]byte, info.CertTableSize)
	if _, err := f.ReadAt(certTable, int64(info.CertTableOffset)); err != nil {
		return nil, 0, 0, 0, fmt.Errorf("read certificate table: %w", err)
	}

	// 读取 CheckSum
	var csBuf [4]byte
	if _, err := f.ReadAt(csBuf[:], int64(info.ChecksumOffset)); err != nil {
		return nil, 0, 0, 0, fmt.Errorf("read checksum: %w", err)
	}
	checksum = binary.LittleEndian.Uint32(csBuf[:])

	return certTable, checksum, info.CertTableOffset, info.CertTableSize, nil
}

// ExtractCertTable 仅提取 Certificate Table 字节（不需要 checksum 时使用）
func ExtractCertTable(filePath string) ([]byte, error) {
	certTable, _, _, _, err := ExtractSignatureData(filePath)
	return certTable, err
}

// ReadFileRange 从文件中读取指定范围的字节
func ReadFileRange(filePath string, offset int64, size int) ([]byte, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	buf := make([]byte, size)
	n, err := f.ReadAt(buf, offset)
	if err != nil && err != io.EOF {
		return nil, err
	}
	return buf[:n], nil
}
