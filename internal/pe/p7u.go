package pe

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"math/big"
)

// OID 定义 (Authenticode / PKCS#7 相关)
var (
	oidData                   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSignedData             = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidSpcIndirectDataContent = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 4}
	oidSpcPeImageData         = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 15}
	oidSHA256                 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidRSAEncryption          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidContentType            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidSpcSpOpusInfo          = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 12}
	oidSpcStatementType       = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 11}
	oidMsCodeInd              = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 21}
	oidMessageDigest          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidRFC3161CounterSign     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 3, 3, 1}
)

// BuildUnsignedPKCS7 构造 Authenticode unsigned PKCS#7 (.p7u)
// digest: Authenticode SHA-256 摘要 (32 bytes)
// certDER: 签名证书 DER 编码
func BuildUnsignedPKCS7(digest []byte, certDER []byte) ([]byte, error) {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse cert: %w", err)
	}

	// 1. 构造 SpcIndirectDataContent
	indirectData, err := buildSpcIndirectDataContent(digest)
	if err != nil {
		return nil, err
	}

	// 2. 构造 SignerInfo（签名值为空）
	signerInfo, err := buildSignerInfo(cert, indirectData)
	if err != nil {
		return nil, err
	}

	// 3. 构造 SignedData
	signedData, err := buildSignedData(cert, indirectData, signerInfo)
	if err != nil {
		return nil, err
	}

	// 4. 包装为 ContentInfo
	// 注意: Go 的 asn1.Marshal 对 RawValue 字段会忽略 struct tag (explicit,tag:0)，
	// RawValue 会被原样编码。所以需要手动构造:
	//   [0] EXPLICIT { SEQUENCE { signedData elements } }
	// 先将 signedData 包装为 SEQUENCE (SignedData 是 SEQUENCE 类型),
	// 再作为 [0] 的 Bytes。
	signedDataSeqDER, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true,
		Bytes: signedData,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal SignedData SEQUENCE: %w", err)
	}

	contentInfo := pkcs7ContentInfo{
		ContentType: oidSignedData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: signedDataSeqDER},
	}

	return asn1.Marshal(contentInfo)
}

// BuildWinCertificate 将 PKCS#7 DER 包装为 WIN_CERTIFICATE 结构
func BuildWinCertificate(pkcs7DER []byte) []byte {
	totalLen := 8 + len(pkcs7DER)
	// 按 8 字节对齐
	padLen := (8 - totalLen%8) % 8
	alignedLen := totalLen + padLen
	buf := make([]byte, alignedLen)
	binary.LittleEndian.PutUint32(buf[0:4], uint32(alignedLen)) // dwLength (含对齐填充)
	binary.LittleEndian.PutUint16(buf[4:6], 0x0200)            // wRevision = WIN_CERT_REVISION_2_0
	binary.LittleEndian.PutUint16(buf[6:8], 0x0002)            // wCertificateType = WIN_CERT_TYPE_PKCS_SIGNED_DATA
	copy(buf[8:], pkcs7DER)
	return buf
}

// ASN.1 结构定义

type pkcs7ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type issuerAndSerialNumber struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

type attribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue `asn1:"set"`
}

type signerInfo struct {
	Version            int
	IssuerAndSerial    issuerAndSerialNumber
	DigestAlgorithm    algorithmIdentifier
	AuthenticatedAttrs asn1.RawValue  `asn1:"optional,tag:0"`
	DigestEncAlgorithm algorithmIdentifier
	EncryptedDigest    []byte
	UnauthenticatedAttrs asn1.RawValue `asn1:"optional,tag:1"`
}

type spcPeImageData struct {
	Flags asn1.BitString
	File  asn1.RawValue `asn1:"optional,tag:0"`
}

type spcAttributeTypeAndOptionalValue struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"optional"`
}

type digestInfo struct {
	DigestAlgorithm algorithmIdentifier
	Digest          []byte
}

type spcIndirectDataContent struct {
	Data          spcAttributeTypeAndOptionalValue
	MessageDigest digestInfo
}

func buildSpcIndirectDataContent(digest []byte) ([]byte, error) {
	// SpcPeImageData — 包含 flags 和 file 两个字段
	// file 字段是 SpcLink，Authenticode 规范要求必须存在。
	// 使用 file → SpcString(unicode) 指向空 BMPString，
	// 与 signtool 生成的签名一致：
	//   [0] CONSTRUCTED {          -- SpcPeImageData.file
	//     [2] CONSTRUCTED {        -- SpcLink CHOICE: file (SpcString)
	//       [0] PRIMITIVE (empty)  -- SpcString CHOICE: unicode (empty BMPString)
	//     }
	//   }
	spcLinkFileContent := []byte{0xa2, 0x02, 0x80, 0x00}
	peImageData := spcPeImageData{
		Flags: asn1.BitString{Bytes: nil, BitLength: 0},
		File: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      spcLinkFileContent,
		},
	}
	peImageDataDER, err := asn1.Marshal(peImageData)
	if err != nil {
		return nil, err
	}

	content := spcIndirectDataContent{
		Data: spcAttributeTypeAndOptionalValue{
			Type:  oidSpcPeImageData,
			Value: asn1.RawValue{FullBytes: peImageDataDER},
		},
		MessageDigest: digestInfo{
			DigestAlgorithm: algorithmIdentifier{
				Algorithm:  oidSHA256,
				Parameters: asn1.RawValue{Tag: asn1.TagNull},
			},
			Digest: digest,
		},
	}

	return asn1.Marshal(content)
}

func buildSignerInfo(cert *x509.Certificate, indirectData []byte) ([]byte, error) {
	// 复用 buildAuthAttrsContent 构造 authenticated attributes
	authAttrsBytes, err := buildAuthAttrsContent(cert, indirectData)
	if err != nil {
		return nil, err
	}

	si := signerInfo{
		Version: 1,
		IssuerAndSerial: issuerAndSerialNumber{
			Issuer:       asn1.RawValue{FullBytes: cert.RawIssuer},
			SerialNumber: cert.SerialNumber,
		},
		DigestAlgorithm: algorithmIdentifier{
			Algorithm:  oidSHA256,
			Parameters: asn1.RawValue{Tag: asn1.TagNull},
		},
		AuthenticatedAttrs: asn1.RawValue{
			Class:      2,
			Tag:        0,
			IsCompound: true,
			Bytes:      authAttrsBytes,
		},
		DigestEncAlgorithm: algorithmIdentifier{
			Algorithm:  oidRSAEncryption,
			Parameters: asn1.RawValue{Tag: asn1.TagNull},
		},
		EncryptedDigest: []byte{}, // 空签名值 — 由 signtool /ds 填充
	}

	return asn1.Marshal(si)
}

func buildSignedData(cert *x509.Certificate, indirectData []byte, signerInfoDER []byte) ([]byte, error) {
	// ContentInfo for SpcIndirectDataContent
	// Go 的 asn1.Marshal 对 RawValue 忽略 struct tag，
	// 所以 Class:2 Tag:0 直接编码为 [0]，Bytes 中的 indirectData 已是完整 DER (30 ...),
	// 最终得到正确的: [0] EXPLICIT { SEQUENCE { SpcIndirectDataContent } }
	contentInfo := struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"explicit,tag:0"`
	}{
		ContentType: oidSpcIndirectDataContent,
		Content:     asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: indirectData},
	}
	contentInfoDER, err := asn1.Marshal(contentInfo)
	if err != nil {
		return nil, err
	}

	// DigestAlgorithms SET
	digestAlgDER, err := asn1.Marshal(algorithmIdentifier{
		Algorithm:  oidSHA256,
		Parameters: asn1.RawValue{Tag: asn1.TagNull},
	})
	if err != nil {
		return nil, err
	}
	digestAlgSet := asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSet,
		IsCompound: true,
		Bytes:      digestAlgDER,
	}
	digestAlgSetDER, err := asn1.Marshal(digestAlgSet)
	if err != nil {
		return nil, err
	}

	// Certificates
	certSet := asn1.RawValue{
		Class:      2,
		Tag:        0,
		IsCompound: true,
		Bytes:      cert.Raw,
	}
	certSetDER, err := asn1.Marshal(certSet)
	if err != nil {
		return nil, err
	}

	// SignerInfos SET
	signerInfoSet := asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSet,
		IsCompound: true,
		Bytes:      signerInfoDER,
	}
	signerInfoSetDER, err := asn1.Marshal(signerInfoSet)
	if err != nil {
		return nil, err
	}

	// version INTEGER (1)
	versionDER, err := asn1.Marshal(1)
	if err != nil {
		return nil, err
	}

	// 拼接 SignedData 内容
	signedDataBytes := append(versionDER, digestAlgSetDER...)
	signedDataBytes = append(signedDataBytes, contentInfoDER...)
	signedDataBytes = append(signedDataBytes, certSetDER...)
	signedDataBytes = append(signedDataBytes, signerInfoSetDER...)

	return signedDataBytes, nil
}

func buildSignedDataMultiCert(certDERs [][]byte, indirectData []byte, signerInfoDER []byte) ([]byte, error) {
	contentInfo := struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"explicit,tag:0"`
	}{
		ContentType: oidSpcIndirectDataContent,
		Content:     asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: indirectData},
	}
	contentInfoDER, err := asn1.Marshal(contentInfo)
	if err != nil {
		return nil, err
	}

	digestAlgDER, err := asn1.Marshal(algorithmIdentifier{
		Algorithm:  oidSHA256,
		Parameters: asn1.RawValue{Tag: asn1.TagNull},
	})
	if err != nil {
		return nil, err
	}
	digestAlgSetDER, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true,
		Bytes: digestAlgDER,
	})
	if err != nil {
		return nil, err
	}

	var allCertsBytes []byte
	for _, der := range certDERs {
		allCertsBytes = append(allCertsBytes, der...)
	}
	certSetDER, err := asn1.Marshal(asn1.RawValue{
		Class: 2, Tag: 0, IsCompound: true,
		Bytes: allCertsBytes,
	})
	if err != nil {
		return nil, err
	}

	signerInfoSetDER, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true,
		Bytes: signerInfoDER,
	})
	if err != nil {
		return nil, err
	}

	versionDER, err := asn1.Marshal(1)
	if err != nil {
		return nil, err
	}

	signedDataBytes := append(versionDER, digestAlgSetDER...)
	signedDataBytes = append(signedDataBytes, contentInfoDER...)
	signedDataBytes = append(signedDataBytes, certSetDER...)
	signedDataBytes = append(signedDataBytes, signerInfoSetDER...)

	return signedDataBytes, nil
}

func buildAttr(oid asn1.ObjectIdentifier, value interface{}) ([]byte, error) {
	valDER, err := asn1.Marshal(value)
	if err != nil {
		return nil, err
	}
	valSet := asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSet,
		IsCompound: true,
		Bytes:      valDER,
	}
	valSetDER, err := asn1.Marshal(valSet)
	if err != nil {
		return nil, err
	}
	oidDER, err := asn1.Marshal(oid)
	if err != nil {
		return nil, err
	}
	attrSeq := asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      append(oidDER, valSetDER...),
	}
	return asn1.Marshal(attrSeq)
}

// BuildSignedPKCS7 构造已签名的 PKCS#7 (完整 Authenticode 签名)
//
// 参数:
//   - digest:       Authenticode SHA-256 摘要 (32 bytes)
//   - certDER:      签名证书 DER 编码
//   - chainDERs:    证书链 DER 编码列表（中间 CA 等，可为 nil）
//   - rsaSignature: RSA-PKCS1v15-SHA256 签名值 (big-endian)
//   - tsToken:      RFC 3161 时间戳令牌 (可为 nil)
func BuildSignedPKCS7(digest []byte, certDER []byte, chainDERs [][]byte, rsaSignature []byte, tsToken []byte) ([]byte, error) {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse cert: %w", err)
	}

	// 1. 构造 SpcIndirectDataContent
	indirectData, err := buildSpcIndirectDataContent(digest)
	if err != nil {
		return nil, err
	}

	// 2. 构造 SignerInfo（包含签名值）
	signedSignerInfo, err := buildSignedSignerInfo(cert, indirectData, rsaSignature, tsToken)
	if err != nil {
		return nil, err
	}

	// 3. 构造 SignedData
	allCertDERs := [][]byte{certDER}
	allCertDERs = append(allCertDERs, chainDERs...)
	signedData, err := buildSignedDataMultiCert(allCertDERs, indirectData, signedSignerInfo)
	if err != nil {
		return nil, err
	}

	// 4. 包装为 ContentInfo (与 BuildUnsignedPKCS7 相同逻辑)
	signedDataSeqDER, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true,
		Bytes: signedData,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal SignedData SEQUENCE: %w", err)
	}

	contentInfo := pkcs7ContentInfo{
		ContentType: oidSignedData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: signedDataSeqDER},
	}

	return asn1.Marshal(contentInfo)
}

// AuthAttrsDigest 构造 authenticatedAttributes 并计算其 SHA-256 摘要
// 返回 hex 编码的摘要（可直接发送给 /api/raw-sign）
//
// PKCS#7 规范要求: 签名时 authenticatedAttributes 使用 SET OF (tag 0x31) 编码,
// 而非 SignerInfo 中的 IMPLICIT [0] (tag 0xA0)
func AuthAttrsDigest(authenticodeDigest []byte, certDER []byte) (string, error) {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return "", fmt.Errorf("parse cert: %w", err)
	}

	// 构造 SpcIndirectDataContent（用于计算 MessageDigest attribute 值）
	indirectData, err := buildSpcIndirectDataContent(authenticodeDigest)
	if err != nil {
		return "", err
	}

	// 构造 authAttrs 内容
	authAttrsBytes, err := buildAuthAttrsContent(cert, indirectData)
	if err != nil {
		return "", err
	}

	// 包装为 SET OF (tag 0x31) 用于签名
	authAttrsForSign := asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSet,
		IsCompound: true,
		Bytes:      authAttrsBytes,
	}
	authAttrsDER, err := asn1.Marshal(authAttrsForSign)
	if err != nil {
		return "", fmt.Errorf("marshal authAttrs for signing: %w", err)
	}

	// SHA-256
	h := sha256.Sum256(authAttrsDER)
	return fmt.Sprintf("%x", h), nil
}

// buildAuthAttrsContent 构造 authenticatedAttributes 的内容部分
func buildAuthAttrsContent(cert *x509.Certificate, indirectData []byte) ([]byte, error) {
	// 1. ContentType = SpcIndirectDataContent
	contentTypeAttr, err := buildAttr(oidContentType, oidSpcIndirectDataContent)
	if err != nil {
		return nil, err
	}

	// 2. SpcSpOpusInfo (空)
	opusInfoAttr, err := buildOpusInfoAttr()
	if err != nil {
		return nil, err
	}

	// 3. SpcStatementType = Microsoft Individual Code Signing
	statementTypeAttr, err := buildStatementTypeAttr()
	if err != nil {
		return nil, err
	}

	// 4. MessageDigest = SHA-256(indirectData DER)
	msgDigestBytes := sha256.Sum256(indirectData)
	msgDigestAttr, err := buildAttr(oidMessageDigest, asn1.RawValue{Tag: asn1.TagOctetString, Bytes: msgDigestBytes[:]})
	if err != nil {
		return nil, err
	}

	attrs := append(append(append(contentTypeAttr, opusInfoAttr...), statementTypeAttr...), msgDigestAttr...)

	return attrs, nil
}

// buildSignedSignerInfo 构造包含签名值的 SignerInfo
func buildSignedSignerInfo(cert *x509.Certificate, indirectData []byte, rsaSignature []byte, tsToken []byte) ([]byte, error) {
	authAttrsBytes, err := buildAuthAttrsContent(cert, indirectData)
	if err != nil {
		return nil, err
	}

	si := signerInfo{
		Version: 1,
		IssuerAndSerial: issuerAndSerialNumber{
			Issuer:       asn1.RawValue{FullBytes: cert.RawIssuer},
			SerialNumber: cert.SerialNumber,
		},
		DigestAlgorithm: algorithmIdentifier{
			Algorithm:  oidSHA256,
			Parameters: asn1.RawValue{Tag: asn1.TagNull},
		},
		AuthenticatedAttrs: asn1.RawValue{
			Class:      2,
			Tag:        0,
			IsCompound: true,
			Bytes:      authAttrsBytes,
		},
		DigestEncAlgorithm: algorithmIdentifier{
			Algorithm:  oidRSAEncryption,
			Parameters: asn1.RawValue{Tag: asn1.TagNull},
		},
		EncryptedDigest: rsaSignature, // 已签名的值
	}

	// RFC 3161 时间戳反签名
	if len(tsToken) > 0 {
		unauthAttr, err := buildTimestampUnauthAttr(tsToken)
		if err != nil {
			return nil, fmt.Errorf("build timestamp unauth attr: %w", err)
		}
		si.UnauthenticatedAttrs = asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        1,
			IsCompound: true,
			Bytes:      unauthAttr,
		}
	}

	return asn1.Marshal(si)
}

func buildOpusInfoAttr() ([]byte, error) {
	// SpcSpOpusInfo — 空序列
	emptySeqDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      []byte{},
	})
	if err != nil {
		return nil, err
	}
	valSet := asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSet,
		IsCompound: true,
		Bytes:      emptySeqDER,
	}
	valSetDER, err := asn1.Marshal(valSet)
	if err != nil {
		return nil, err
	}
	oidDER, err := asn1.Marshal(oidSpcSpOpusInfo)
	if err != nil {
		return nil, err
	}
	attrSeq := asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      append(oidDER, valSetDER...),
	}
	return asn1.Marshal(attrSeq)
}

func buildStatementTypeAttr() ([]byte, error) {
	// SpcStatementType = { oidMsCodeInd }
	oidValDER, err := asn1.Marshal(oidMsCodeInd)
	if err != nil {
		return nil, err
	}
	seqDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      oidValDER,
	})
	if err != nil {
		return nil, err
	}
	valSet := asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSet,
		IsCompound: true,
		Bytes:      seqDER,
	}
	valSetDER, err := asn1.Marshal(valSet)
	if err != nil {
		return nil, err
	}
	oidDER, err := asn1.Marshal(oidSpcStatementType)
	if err != nil {
		return nil, err
	}
	attrSeq := asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      append(oidDER, valSetDER...),
	}
	return asn1.Marshal(attrSeq)
}

// buildTimestampUnauthAttr 构造 UnauthenticatedAttrs 中的 RFC 3161 时间戳属性内容
func buildTimestampUnauthAttr(tsToken []byte) ([]byte, error) {
	oidDER, err := asn1.Marshal(oidRFC3161CounterSign)
	if err != nil {
		return nil, err
	}
	valSet := asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSet,
		IsCompound: true,
		Bytes:      tsToken,
	}
	valSetDER, err := asn1.Marshal(valSet)
	if err != nil {
		return nil, err
	}
	attrSeq := asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      append(oidDER, valSetDER...),
	}
	return asn1.Marshal(attrSeq)
}
