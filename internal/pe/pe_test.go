package pe

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"math/big"
	"os"
	"testing"
	"time"
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

// buildTestPEWithSize 构建指定大小的最小 PE32+ 文件（用于测试对齐）
func buildTestPEWithSize(t *testing.T, fileSize int) string {
	t.Helper()
	f, err := os.CreateTemp("", "test-*.exe")
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	defer f.Close()

	const (
		peOff     = 0x40
		optOff    = peOff + 24
		csOff     = optOff + 64
		ddStart   = optOff + 112
		secDirOff = ddStart + 4*8
	)

	if fileSize < 0x200 {
		fileSize = 0x200
	}
	buf := make([]byte, fileSize)

	buf[0] = 'M'
	buf[1] = 'Z'
	binary.LittleEndian.PutUint32(buf[0x3C:], uint32(peOff))
	buf[peOff+0] = 'P'
	buf[peOff+1] = 'E'
	binary.LittleEndian.PutUint16(buf[peOff+4:], 0x8664)
	binary.LittleEndian.PutUint16(buf[peOff+6:], 0)
	binary.LittleEndian.PutUint16(buf[peOff+20:], 240)
	binary.LittleEndian.PutUint16(buf[peOff+22:], 0x2102)
	binary.LittleEndian.PutUint16(buf[optOff:], 0x020B)

	for i := secDirOff + 8; i < fileSize; i++ {
		buf[i] = byte(i & 0xFF)
	}

	if _, err := f.Write(buf); err != nil {
		t.Fatalf("write test PE: %v", err)
	}
	return f.Name()
}

func TestInjectSignature_UnalignedFileSize(t *testing.T) {
	// 测试文件大小不是 8 字节对齐时，注入签名后 CertTableOffset 应 8 字节对齐
	for _, size := range []int{0x201, 0x203, 0x205, 0x207} {
		t.Run(
			func() string { return fmt.Sprintf("size=0x%X", size) }(),
			func(t *testing.T) {
				path := buildTestPEWithSize(t, size)
				defer os.Remove(path)

				info, err := ParsePE(path)
				if err != nil {
					t.Fatalf("ParsePE: %v", err)
				}

				if info.FileSize%8 == 0 {
					t.Skip("file already 8-byte aligned")
				}

				// 构造假的 WIN_CERTIFICATE
				fakeCertTable := make([]byte, 16)
				binary.LittleEndian.PutUint32(fakeCertTable[0:4], 16)
				binary.LittleEndian.PutUint16(fakeCertTable[4:6], 0x200)
				binary.LittleEndian.PutUint16(fakeCertTable[6:8], 0x002)

				if err := InjectSignature(path, info, fakeCertTable); err != nil {
					t.Fatalf("InjectSignature: %v", err)
				}

				info2, err := ParsePE(path)
				if err != nil {
					t.Fatalf("ParsePE after inject: %v", err)
				}

				// CertTableOffset 应 8 字节对齐
				if info2.CertTableOffset%8 != 0 {
					t.Errorf("CertTableOffset=0x%X is not 8-byte aligned", info2.CertTableOffset)
				}

				// CertTableOffset 应 >= 原始文件大小
				if int64(info2.CertTableOffset) < info.FileSize {
					t.Errorf("CertTableOffset=0x%X < original FileSize=0x%X",
						info2.CertTableOffset, info.FileSize)
				}

				// 提取证书表应与原始一致
				extracted, _, _, _, err := ExtractSignatureData(path)
				if err != nil {
					t.Fatalf("ExtractSignatureData: %v", err)
				}
				for i := range fakeCertTable {
					if extracted[i] != fakeCertTable[i] {
						t.Errorf("byte %d: got 0x%02X, want 0x%02X", i, extracted[i], fakeCertTable[i])
					}
				}
			},
		)
	}
}

func TestDigest_AlignedConsistency(t *testing.T) {
	// 验证：对齐文件和不对齐文件在填充零字节后，摘要应一致
	// 即 "文件 A (0x200 bytes)" 与 "文件 B (0x203 bytes + 5 zero padding)" 的摘要
	// 在文件 A 的 0x200~0x207 全为零时应一致。
	alignedPath := buildTestPEWithSize(t, 0x200) // 已对齐
	defer os.Remove(alignedPath)

	unalignedPath := buildTestPEWithSize(t, 0x203) // 不对齐，多 3 字节
	defer os.Remove(unalignedPath)

	// 将不对齐文件的多余 3 字节置零（模拟全零尾部）
	uf, err := os.OpenFile(unalignedPath, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	uf.WriteAt([]byte{0, 0, 0}, 0x200)
	uf.Close()

	// 同样将对齐文件末尾追加 3 个零再追加 5 个零，使其达到 0x208
	// 不，更好的测试方式是：
	// 对齐文件 0x200 → computeDigest 哈希到 0x200（已对齐，无填充）
	// 不对齐文件 0x203 → computeDigest 哈希到 0x208（+5 零填充）
	// 所以它们不会相同。测试只验证不对齐文件的摘要是确定性的。

	info1, _ := ParsePE(unalignedPath)
	d1, err := ComputeAuthenticodeDigest(unalignedPath, info1)
	if err != nil {
		t.Fatalf("digest1: %v", err)
	}
	d2, err := ComputeAuthenticodeDigest(unalignedPath, info1)
	if err != nil {
		t.Fatalf("digest2: %v", err)
	}

	for i := range d1 {
		if d1[i] != d2[i] {
			t.Fatal("digest of unaligned file is not deterministic")
		}
	}
	t.Logf("unaligned file (0x203) digest: %x", d1)
}

// generateTestCert 生成一个自签名测试证书
func generateTestCert(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return certDER
}

// TestBuildSignedPKCS7_ASN1Structure 验证 BuildSignedPKCS7 生成的 ASN.1 结构正确
// 关键检查: 外层 ContentInfo 的 content 是 [0] EXPLICIT { SEQUENCE { ... } }
// 而不是错误的 [0] EXPLICIT { [0] { ... } }（双重 [0] 嵌套）
func TestBuildSignedPKCS7_ASN1Structure(t *testing.T) {
	certDER := generateTestCert(t)
	fakeDigest := make([]byte, 32)
	fakeRSASig := make([]byte, 256)

	pkcs7DER, err := BuildSignedPKCS7(fakeDigest, certDER, nil, fakeRSASig, nil)
	if err != nil {
		t.Fatalf("BuildSignedPKCS7: %v", err)
	}

	// 解析外层 ContentInfo SEQUENCE
	var outer asn1.RawValue
	rest, err := asn1.Unmarshal(pkcs7DER, &outer)
	if err != nil {
		t.Fatalf("unmarshal outer: %v", err)
	}
	if len(rest) != 0 {
		t.Fatalf("trailing bytes: %d", len(rest))
	}
	if outer.Tag != asn1.TagSequence {
		t.Fatalf("outer tag: got 0x%02X, want 0x10 (SEQUENCE)", outer.Tag)
	}

	// 解析 ContentInfo 内部: OID + [0] EXPLICIT content
	var oid asn1.ObjectIdentifier
	rest, err = asn1.Unmarshal(outer.Bytes, &oid)
	if err != nil {
		t.Fatalf("unmarshal OID: %v", err)
	}
	if !oid.Equal(oidSignedData) {
		t.Fatalf("contentType: got %v, want %v", oid, oidSignedData)
	}

	// 解析 [0] EXPLICIT wrapper
	var explicit0 asn1.RawValue
	rest, err = asn1.Unmarshal(rest, &explicit0)
	if err != nil {
		t.Fatalf("unmarshal [0] wrapper: %v", err)
	}
	if explicit0.Class != asn1.ClassContextSpecific || explicit0.Tag != 0 {
		t.Fatalf("[0] wrapper: got class=%d tag=%d, want class=2 tag=0", explicit0.Class, explicit0.Tag)
	}

	// 关键检查: [0] 内部的第一个元素应该是 SEQUENCE (0x30)，不是 [0] (0xa0)
	var signedDataSeq asn1.RawValue
	_, err = asn1.Unmarshal(explicit0.Bytes, &signedDataSeq)
	if err != nil {
		t.Fatalf("unmarshal SignedData: %v", err)
	}

	if signedDataSeq.Class != asn1.ClassUniversal || signedDataSeq.Tag != asn1.TagSequence {
		t.Errorf("SignedData: got class=%d tag=%d (0x%02X), want class=0 tag=16 (0x30 SEQUENCE)",
			signedDataSeq.Class, signedDataSeq.Tag, signedDataSeq.Tag|(signedDataSeq.Class<<6))
		if signedDataSeq.Class == asn1.ClassContextSpecific && signedDataSeq.Tag == 0 {
			t.Error("BUG: SignedData is [0] CONTEXT instead of SEQUENCE — double [0] wrapping detected!")
		}
	}

	// 解析 SignedData 内部: version, digestAlgorithms, encapContentInfo, ...
	// 检查 encapContentInfo 的 content [0] 也是正确的
	var version int
	inner := signedDataSeq.Bytes
	inner, err = asn1.Unmarshal(inner, &version)
	if err != nil {
		t.Fatalf("unmarshal version: %v", err)
	}
	if version != 1 {
		t.Errorf("version: got %d, want 1", version)
	}

	// Skip digestAlgorithms SET
	var digestAlgs asn1.RawValue
	inner, err = asn1.Unmarshal(inner, &digestAlgs)
	if err != nil {
		t.Fatalf("unmarshal digestAlgorithms: %v", err)
	}

	// encapContentInfo SEQUENCE
	var encapCI asn1.RawValue
	_, err = asn1.Unmarshal(inner, &encapCI)
	if err != nil {
		t.Fatalf("unmarshal encapContentInfo: %v", err)
	}
	if encapCI.Tag != asn1.TagSequence {
		t.Fatalf("encapContentInfo tag: got 0x%02X, want SEQUENCE", encapCI.Tag)
	}

	// 解析 encapContentInfo: OID + [0] EXPLICIT { SpcIndirectDataContent }
	var ecOID asn1.ObjectIdentifier
	ecRest, err := asn1.Unmarshal(encapCI.Bytes, &ecOID)
	if err != nil {
		t.Fatalf("unmarshal encapContentInfo OID: %v", err)
	}

	var ecContent asn1.RawValue
	_, err = asn1.Unmarshal(ecRest, &ecContent)
	if err != nil {
		t.Fatalf("unmarshal encapContentInfo [0]: %v", err)
	}
	if ecContent.Class != asn1.ClassContextSpecific || ecContent.Tag != 0 {
		t.Fatalf("encapContentInfo content: got class=%d tag=%d, want [0]", ecContent.Class, ecContent.Tag)
	}

	// 关键检查: [0] 内部应该是 SEQUENCE（SpcIndirectDataContent），不是另一个 [0]
	var spcContent asn1.RawValue
	_, err = asn1.Unmarshal(ecContent.Bytes, &spcContent)
	if err != nil {
		t.Fatalf("unmarshal SpcIndirectDataContent: %v", err)
	}
	if spcContent.Class != asn1.ClassUniversal || spcContent.Tag != asn1.TagSequence {
		t.Errorf("SpcIndirectDataContent: got class=%d tag=%d, want SEQUENCE",
			spcContent.Class, spcContent.Tag)
		if spcContent.Class == asn1.ClassContextSpecific && spcContent.Tag == 0 {
			t.Error("BUG: SpcIndirectDataContent is [0] CONTEXT — double wrapping in encapContentInfo!")
		}
	}

	t.Logf("PKCS#7 ASN.1 structure is correct: ContentInfo > [0] > SEQUENCE(SignedData) > ... > [0] > SEQUENCE(SpcIndirectDataContent)")
}

// TestBuildUnsignedPKCS7_ASN1Structure 验证 BuildUnsignedPKCS7 的 ASN.1 结构也正确
func TestBuildUnsignedPKCS7_ASN1Structure(t *testing.T) {
	certDER := generateTestCert(t)
	fakeDigest := make([]byte, 32)

	pkcs7DER, err := BuildUnsignedPKCS7(fakeDigest, certDER)
	if err != nil {
		t.Fatalf("BuildUnsignedPKCS7: %v", err)
	}

	// 解析外层
	var outer asn1.RawValue
	_, err = asn1.Unmarshal(pkcs7DER, &outer)
	if err != nil {
		t.Fatalf("unmarshal outer: %v", err)
	}

	// OID
	var oid asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal(outer.Bytes, &oid)
	if err != nil {
		t.Fatalf("unmarshal OID: %v", err)
	}

	// [0] EXPLICIT
	var explicit0 asn1.RawValue
	_, err = asn1.Unmarshal(rest, &explicit0)
	if err != nil {
		t.Fatalf("unmarshal [0]: %v", err)
	}

	// [0] 内部应该是 SEQUENCE
	var signedDataSeq asn1.RawValue
	_, err = asn1.Unmarshal(explicit0.Bytes, &signedDataSeq)
	if err != nil {
		t.Fatalf("unmarshal SignedData: %v", err)
	}

	if signedDataSeq.Class != asn1.ClassUniversal || signedDataSeq.Tag != asn1.TagSequence {
		t.Errorf("SignedData in unsigned PKCS7: got class=%d tag=%d, want SEQUENCE",
			signedDataSeq.Class, signedDataSeq.Tag)
	} else {
		t.Log("Unsigned PKCS#7 ASN.1 structure is correct")
	}
}

// TestBuildSignedPKCS7_WithTimestamp 验证带时间戳的 PKCS#7 结构
// 检查 SignerInfo 中 UnauthenticatedAttrs 包含 RFC 3161 countersign OID
func TestBuildSignedPKCS7_WithTimestamp(t *testing.T) {
	certDER := generateTestCert(t)
	fakeDigest := make([]byte, 32)
	fakeRSASig := make([]byte, 256)
	// 构造一个最小的合法 ASN.1 SEQUENCE 作为 mock tsToken
	fakeTsToken, _ := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true,
		Bytes: []byte{0x02, 0x01, 0x00}, // INTEGER 0
	})

	pkcs7DER, err := BuildSignedPKCS7(fakeDigest, certDER, nil, fakeRSASig, fakeTsToken)
	if err != nil {
		t.Fatalf("BuildSignedPKCS7 with timestamp: %v", err)
	}

	// 解析到 SignedData 内部
	var outer asn1.RawValue
	rest, _ := asn1.Unmarshal(pkcs7DER, &outer)
	_ = rest

	// ContentInfo → [0] → SEQUENCE(SignedData)
	var oid asn1.ObjectIdentifier
	rest, _ = asn1.Unmarshal(outer.Bytes, &oid)
	var explicit0 asn1.RawValue
	rest, _ = asn1.Unmarshal(rest, &explicit0)
	var signedDataSeq asn1.RawValue
	_, _ = asn1.Unmarshal(explicit0.Bytes, &signedDataSeq)

	// SignedData: version, digestAlgs, contentInfo, [0]certs, signerInfos
	inner := signedDataSeq.Bytes
	var version int
	inner, _ = asn1.Unmarshal(inner, &version)
	var digestAlgs asn1.RawValue
	inner, _ = asn1.Unmarshal(inner, &digestAlgs)
	var contentInfo asn1.RawValue
	inner, _ = asn1.Unmarshal(inner, &contentInfo)
	var certs asn1.RawValue
	inner, _ = asn1.Unmarshal(inner, &certs)
	// inner 现在是 SignerInfos SET
	var signerInfosSet asn1.RawValue
	_, _ = asn1.Unmarshal(inner, &signerInfosSet)

	// 解析 SignerInfo SEQUENCE
	var si asn1.RawValue
	_, _ = asn1.Unmarshal(signerInfosSet.Bytes, &si)

	// 遍历 SignerInfo 字段，找到 [1] UnauthenticatedAttrs
	siInner := si.Bytes
	foundUnauth := false
	for len(siInner) > 0 {
		var field asn1.RawValue
		var err error
		siInner, err = asn1.Unmarshal(siInner, &field)
		if err != nil {
			break
		}
		if field.Class == asn1.ClassContextSpecific && field.Tag == 1 {
			foundUnauth = true
			// 内部应该是 SEQUENCE { OID(1.3.6.1.4.1.311.3.3.1), SET { tsToken } }
			var attrSeq asn1.RawValue
			_, err := asn1.Unmarshal(field.Bytes, &attrSeq)
			if err != nil {
				t.Fatalf("unmarshal unauth attr SEQUENCE: %v", err)
			}
			if attrSeq.Tag != asn1.TagSequence {
				t.Fatalf("unauth attr: expected SEQUENCE, got tag=%d", attrSeq.Tag)
			}
			var attrOID asn1.ObjectIdentifier
			attrRest, err := asn1.Unmarshal(attrSeq.Bytes, &attrOID)
			if err != nil {
				t.Fatalf("unmarshal unauth attr OID: %v", err)
			}
			expectedOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 3, 3, 1}
			if !attrOID.Equal(expectedOID) {
				t.Fatalf("unauth attr OID: got %v, want %v", attrOID, expectedOID)
			}
			// 后面应该是 SET
			var valSet asn1.RawValue
			_, err = asn1.Unmarshal(attrRest, &valSet)
			if err != nil {
				t.Fatalf("unmarshal unauth attr SET: %v", err)
			}
			if valSet.Tag != asn1.TagSet {
				t.Fatalf("unauth attr value: expected SET, got tag=%d", valSet.Tag)
			}
			t.Logf("UnauthenticatedAttrs correctly contains RFC 3161 countersign (OID %v)", attrOID)
		}
	}
	if !foundUnauth {
		t.Fatal("SignerInfo missing UnauthenticatedAttrs [1] — timestamp not embedded")
	}
}
