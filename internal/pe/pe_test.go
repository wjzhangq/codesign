package pe

import (
	"encoding/binary"
	"os"
	"testing"
)

// buildTestPE 构建一个用于测试的最小 PE32+ 文件
// 返回文件路径（调用方负责清理）
func buildTestPE(t *testing.T) string {
	t.Helper()
	f, err := os.CreateTemp("", "test-*.exe")
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	defer f.Close()

	// PE 布局:
	// 0x00: DOS Header (64 bytes)
	// 0x3C: e_lfanew = 0x40
	// 0x40: PE signature
	// 0x44: COFF Header (20 bytes)
	// 0x58: Optional Header PE32+ (240 bytes)
	//   0x58+0x40 = 0x98: CheckSum (offset 64 in optional header)
	//   0x58+0x70 = 0xC8: Data Directory start (offset 112 in PE32+ optional header)
	//   0xC8+0x20 = 0xE8: Security Dir Entry (DD[4], 4*8=32 bytes after ddStart)
	// 0x138: Section Table (0 sections)

	const (
		peOff    = 0x40
		optOff   = peOff + 24  // 0x58
		csOff    = optOff + 64 // 0x98
		ddStart  = optOff + 112 // 0xC8 (PE32+)
		secDirOff = ddStart + 4*8 // 0xE8
	)

	fileSize := 0x200 // 512 bytes
	buf := make([]byte, fileSize)

	// DOS Header
	buf[0] = 'M'
	buf[1] = 'Z'
	binary.LittleEndian.PutUint32(buf[0x3C:], uint32(peOff))

	// PE Signature
	buf[peOff+0] = 'P'
	buf[peOff+1] = 'E'
	buf[peOff+2] = 0
	buf[peOff+3] = 0

	// COFF Header
	binary.LittleEndian.PutUint16(buf[peOff+4:], 0x8664)  // Machine: x86-64
	binary.LittleEndian.PutUint16(buf[peOff+6:], 0)       // NumberOfSections: 0
	binary.LittleEndian.PutUint16(buf[peOff+20:], 240)    // SizeOfOptionalHeader: 240
	binary.LittleEndian.PutUint16(buf[peOff+22:], 0x2102) // Characteristics

	// Optional Header PE32+
	binary.LittleEndian.PutUint16(buf[optOff:], 0x020B) // Magic: PE32+

	// CheckSum = 0 (初始)
	binary.LittleEndian.PutUint32(buf[csOff:], 0)

	// Security Dir Entry = 0, 0 (无签名)
	binary.LittleEndian.PutUint32(buf[secDirOff:], 0)   // CertTableOffset
	binary.LittleEndian.PutUint32(buf[secDirOff+4:], 0) // CertTableSize

	// 填充一些数据使文件更"真实"
	for i := secDirOff + 8; i < fileSize; i++ {
		buf[i] = byte(i & 0xFF)
	}

	if _, err := f.Write(buf); err != nil {
		t.Fatalf("write test PE: %v", err)
	}

	return f.Name()
}

func TestParsePE_MinimalPE32Plus(t *testing.T) {
	path := buildTestPE(t)
	defer os.Remove(path)

	info, err := ParsePE(path)
	if err != nil {
		t.Fatalf("ParsePE failed: %v", err)
	}

	// PE32+ 检查
	if !info.IsPE32Plus {
		t.Error("expected IsPE32Plus=true")
	}

	// CheckSum 偏移 = optOff + 64 = 0x58 + 0x40 = 0x98
	const expectedCSOffset = 0x40 + 24 + 64
	if info.ChecksumOffset != expectedCSOffset {
		t.Errorf("ChecksumOffset: got 0x%X, want 0x%X", info.ChecksumOffset, expectedCSOffset)
	}

	// SecurityDir 偏移 = ddStart + 4*8 = (optOff + 112) + 32
	const expectedSecDirOffset = 0x40 + 24 + 112 + 32
	if info.SecurityDirOffset != expectedSecDirOffset {
		t.Errorf("SecurityDirOffset: got 0x%X, want 0x%X", info.SecurityDirOffset, expectedSecDirOffset)
	}

	// 无签名
	if info.CertTableOffset != 0 {
		t.Errorf("CertTableOffset: got 0x%X, want 0", info.CertTableOffset)
	}
	if info.CertTableSize != 0 {
		t.Errorf("CertTableSize: got %d, want 0", info.CertTableSize)
	}

	// 文件大小
	if info.FileSize != 0x200 {
		t.Errorf("FileSize: got %d, want 512", info.FileSize)
	}
}

func TestParsePE_InvalidMZ(t *testing.T) {
	f, _ := os.CreateTemp("", "test-*.exe")
	defer os.Remove(f.Name())
	f.Write([]byte("NOTPE"))
	f.Close()

	_, err := ParsePE(f.Name())
	if err == nil {
		t.Error("expected error for non-PE file")
	}
}

func TestComputeAuthenticodeDigest(t *testing.T) {
	path := buildTestPE(t)
	defer os.Remove(path)

	info, err := ParsePE(path)
	if err != nil {
		t.Fatalf("ParsePE: %v", err)
	}

	digest, err := ComputeAuthenticodeDigest(path, info)
	if err != nil {
		t.Fatalf("ComputeAuthenticodeDigest: %v", err)
	}

	if len(digest) != 32 {
		t.Errorf("digest length: got %d, want 32", len(digest))
	}

	// 相同文件多次计算应得到相同结果
	digest2, _ := ComputeAuthenticodeDigest(path, info)
	for i := range digest {
		if digest[i] != digest2[i] {
			t.Error("digest is not deterministic")
			break
		}
	}
}

func TestComputePEChecksum(t *testing.T) {
	path := buildTestPE(t)
	defer os.Remove(path)

	info, err := ParsePE(path)
	if err != nil {
		t.Fatalf("ParsePE: %v", err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	cs := ComputePEChecksum(f, info.ChecksumOffset)
	// 只要不 panic 且返回合理值就行
	if cs == 0 {
		t.Log("checksum is 0 (possible for small test files)")
	}
	t.Logf("computed checksum: 0x%X", cs)
}

func TestInjectAndExtractSignature(t *testing.T) {
	path := buildTestPE(t)
	defer os.Remove(path)

	info, err := ParsePE(path)
	if err != nil {
		t.Fatalf("ParsePE: %v", err)
	}

	// 构造一个假的 WIN_CERTIFICATE（最小合法结构）
	fakeCertTable := make([]byte, 16)
	binary.LittleEndian.PutUint32(fakeCertTable[0:4], 16)   // dwLength
	binary.LittleEndian.PutUint16(fakeCertTable[4:6], 0x200) // wRevision
	binary.LittleEndian.PutUint16(fakeCertTable[6:8], 0x002) // wCertificateType
	// 8 bytes padding data

	// 注入签名
	if err := InjectSignature(path, info, fakeCertTable); err != nil {
		t.Fatalf("InjectSignature: %v", err)
	}

	// 重新解析验证
	info2, err := ParsePE(path)
	if err != nil {
		t.Fatalf("ParsePE after inject: %v", err)
	}

	if info2.CertTableSize != uint32(len(fakeCertTable)) {
		t.Errorf("CertTableSize: got %d, want %d", info2.CertTableSize, len(fakeCertTable))
	}
	if info2.CertTableOffset == 0 {
		t.Error("CertTableOffset should not be 0 after injection")
	}

	// 提取验证
	extracted, _, _, _, err := ExtractSignatureData(path)
	if err != nil {
		t.Fatalf("ExtractSignatureData: %v", err)
	}

	if len(extracted) != len(fakeCertTable) {
		t.Errorf("extracted cert table length: got %d, want %d", len(extracted), len(fakeCertTable))
	}

	for i := range fakeCertTable {
		if extracted[i] != fakeCertTable[i] {
			t.Errorf("cert table byte %d: got 0x%02X, want 0x%02X", i, extracted[i], fakeCertTable[i])
		}
	}
}
