package pe

import (
	"encoding/binary"
	"fmt"
	"os"
)

// WriteMinimalStubPE 写入一个最小 PE 文件，用于 signtool /di stub 方案
// stub PE 结构满足:
//   - 合法的 MZ 头
//   - 合法的 PE\0\0 签名
//   - CheckSum/SecurityDir 字段对齐与原 PE 一致
//
// 注意: stub 不需要与客户端 PE 内容一致，signtool /di 只关注文件名匹配和基本结构
func WriteMinimalStubPE(path string, info *PEInfo) error {
	// 构建一个最小的 PE32+ 文件
	// 大小至少要覆盖 SecurityDirOffset + 8
	minSize := int(info.SecurityDirOffset) + 8
	if minSize < 512 {
		minSize = 512
	}

	buf := make([]byte, minSize)

	// DOS header: MZ
	buf[0] = 'M'
	buf[1] = 'Z'

	// e_lfanew at offset 0x3C → PE starts at 0x40
	const peOff = 0x40
	binary.LittleEndian.PutUint32(buf[0x3C:], uint32(peOff))

	// PE signature
	buf[peOff+0] = 'P'
	buf[peOff+1] = 'E'
	buf[peOff+2] = 0
	buf[peOff+3] = 0

	// COFF Header
	// Machine: x86-64 (0x8664)
	binary.LittleEndian.PutUint16(buf[peOff+4:], 0x8664)
	// NumberOfSections: 0
	binary.LittleEndian.PutUint16(buf[peOff+6:], 0)
	// SizeOfOptionalHeader: 240 (PE32+ 标准)
	binary.LittleEndian.PutUint16(buf[peOff+20:], 240)
	// Characteristics: executable | DLL (0x2102)
	binary.LittleEndian.PutUint16(buf[peOff+22:], 0x2102)

	// Optional Header
	optOff := peOff + 24
	// Magic: PE32+ (0x20B)
	binary.LittleEndian.PutUint16(buf[optOff:], 0x20B)

	// 确保 buf 足够大
	if int(info.SecurityDirOffset)+8 > len(buf) {
		return fmt.Errorf("stub PE buffer too small: need %d, have %d",
			int(info.SecurityDirOffset)+8, len(buf))
	}

	// Security Directory: offset 和 size 初始为 0（待 signtool /di 填充）
	binary.LittleEndian.PutUint32(buf[info.SecurityDirOffset:], 0)
	binary.LittleEndian.PutUint32(buf[info.SecurityDirOffset+4:], 0)

	if err := os.WriteFile(path, buf, 0600); err != nil {
		return fmt.Errorf("write stub PE: %w", err)
	}

	return nil
}
