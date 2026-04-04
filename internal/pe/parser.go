package pe

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// PEInfo 保存 PE 文件的关键偏移量信息
type PEInfo struct {
	ChecksumOffset    uint32
	SecurityDirOffset uint32
	CertTableOffset   uint32
	CertTableSize     uint32
	OverlayOffset     uint32
	IsPE32Plus        bool
	FileSize          int64
	// 用于 /api/sign 请求中的 pe_info 字段
	NumSections uint16
}

// ParsePE 解析 PE 文件，返回关键偏移量
func ParsePE(path string) (*PEInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open PE file: %w", err)
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat PE file: %w", err)
	}

	info, err := ParsePEFromReader(f)
	if err != nil {
		return nil, err
	}
	// os.File.Stat() size is authoritative; overwrite what ParsePEFromReader computed
	info.FileSize = stat.Size()
	return info, nil
}

// ParsePEFromReader 从 io.ReadSeeker 解析 PE 文件（用于内存中的 PE）
func ParsePEFromReader(r io.ReadSeeker) (*PEInfo, error) {
	fileSize, err := r.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, fmt.Errorf("seek PE end: %w", err)
	}

	readAt := func(buf []byte, off int64) error {
		if _, err := r.Seek(off, io.SeekStart); err != nil {
			return err
		}
		_, err := io.ReadFull(r, buf)
		return err
	}

	info := &PEInfo{FileSize: fileSize}

	// MZ 签名检查
	var mz [2]byte
	if err := readAt(mz[:], 0); err != nil {
		return nil, fmt.Errorf("read MZ signature: %w", err)
	}
	if mz[0] != 'M' || mz[1] != 'Z' {
		return nil, fmt.Errorf("missing MZ signature")
	}

	// e_lfanew → PE offset
	var buf4 [4]byte
	if err := readAt(buf4[:], 0x3C); err != nil {
		return nil, fmt.Errorf("read e_lfanew: %w", err)
	}
	peOff := binary.LittleEndian.Uint32(buf4[:])

	// "PE\0\0" 签名
	if err := readAt(buf4[:], int64(peOff)); err != nil {
		return nil, fmt.Errorf("read PE signature: %w", err)
	}
	if buf4[0] != 'P' || buf4[1] != 'E' || buf4[2] != 0 || buf4[3] != 0 {
		return nil, fmt.Errorf("invalid PE signature at offset 0x%X", peOff)
	}

	// COFF Header (20 bytes after PE signature)
	var coff [20]byte
	if err := readAt(coff[:], int64(peOff+4)); err != nil {
		return nil, fmt.Errorf("read COFF header: %w", err)
	}
	info.NumSections = binary.LittleEndian.Uint16(coff[2:4])
	optSize := binary.LittleEndian.Uint16(coff[16:18])

	// Optional Header
	optOff := peOff + 24
	var magic [2]byte
	if err := readAt(magic[:], int64(optOff)); err != nil {
		return nil, fmt.Errorf("read optional header magic: %w", err)
	}
	info.IsPE32Plus = binary.LittleEndian.Uint16(magic[:]) == 0x20B

	// CheckSum 偏移量: Optional Header + 0x40 (64)
	info.ChecksumOffset = optOff + 64

	// Data Directory 起始偏移:
	//   PE32:    OptionalHeader + 96
	//   PE32+:   OptionalHeader + 112
	var ddStart uint32
	if info.IsPE32Plus {
		ddStart = optOff + 112
	} else {
		ddStart = optOff + 96
	}
	// Security Directory = DataDirectory[4] (index 4, each entry 8 bytes)
	info.SecurityDirOffset = ddStart + 4*8

	// 读取当前 Security Dir 内容 (CertTableOffset + CertTableSize)
	var sd [8]byte
	if err := readAt(sd[:], int64(info.SecurityDirOffset)); err != nil {
		return nil, fmt.Errorf("read security directory: %w", err)
	}
	info.CertTableOffset = binary.LittleEndian.Uint32(sd[0:4])
	info.CertTableSize = binary.LittleEndian.Uint32(sd[4:8])

	// OverlayOffset = max(section.PointerToRawData + SizeOfRawData)
	secTableOff := int64(optOff) + int64(optSize)
	for i := 0; i < int(info.NumSections); i++ {
		var sh [40]byte
		if err := readAt(sh[:], secTableOff+int64(i)*40); err != nil {
			// 如果读取节表失败，停止迭代（部分损坏的PE也能工作）
			break
		}
		rawOff := binary.LittleEndian.Uint32(sh[20:24])
		rawSz := binary.LittleEndian.Uint32(sh[16:20])
		if end := rawOff + rawSz; end > info.OverlayOffset {
			info.OverlayOffset = end
		}
	}

	// 如果没有 sections，使用文件大小作为 overlay
	if info.OverlayOffset == 0 {
		info.OverlayOffset = uint32(fileSize)
	}

	return info, nil
}
