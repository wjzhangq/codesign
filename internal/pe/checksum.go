package pe

import (
	"encoding/binary"
	"io"
)

// ComputePEChecksum 计算 PE 文件的 CheckSum
// 采用 16-bit fold-add 算法，跳过 checksum 字段本身，最后加上文件大小
func ComputePEChecksum(r io.ReadSeeker, csOff uint32) uint32 {
	// 从文件开头开始
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return 0
	}

	var sum uint64
	var pos uint32
	buf := make([]byte, 65536)

	for {
		n, err := r.Read(buf)
		if n > 0 {
			// 处理完整的 16-bit words
			i := 0
			for ; i+1 < n; i += 2 {
				cur := pos + uint32(i)
				// 跳过任何与 CheckSum 字段（4 bytes at csOff）重叠的 16-bit word
				// 条件: word 的右端 > csOff 且 word 的左端 < csOff+4
				if cur+2 > csOff && cur < csOff+4 {
					continue
				}
				word := uint64(binary.LittleEndian.Uint16(buf[i : i+2]))
				sum += word
				sum = (sum & 0xFFFF) + (sum >> 16)
			}
			// 处理末尾单字节（文件大小为奇数时）
			if i < n {
				// 最后一个字节
				curByte := pos + uint32(i)
				if curByte < csOff || curByte >= csOff+4 {
					sum += uint64(buf[i])
					sum = (sum & 0xFFFF) + (sum >> 16)
				}
			}
			pos += uint32(n)
		}
		if err != nil {
			break
		}
	}

	// 最终折叠
	sum = (sum & 0xFFFF) + (sum >> 16)
	sum &= 0xFFFF

	// 加上文件大小
	fileSize, _ := r.Seek(0, io.SeekEnd)
	return uint32(sum) + uint32(fileSize)
}
