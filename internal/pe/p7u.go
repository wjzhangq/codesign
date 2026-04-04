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
	oidSHA256WithRSA          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidContentType            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidSpcSpOpusInfo          = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 12}
	oidMessageDigest          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
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
	contentInfo := pkcs7ContentInfo{
		ContentType: oidSignedData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: signedData},
	}

	return asn1.Marshal(contentInfo)
}

// BuildWinCertificate 将 PKCS#7 DER 包装为 WIN_CERTIFICATE 结构
func BuildWinCertificate(pkcs7DER []byte) []byte {
	totalLen := 8 + len(pkcs7DER)
	// 按 8 字节对齐
	padLen := (8 - totalLen%8) % 8
	buf := make([]byte, totalLen+padLen)
	binary.LittleEndian.PutUint32(buf[0:4], uint32(totalLen))
	binary.LittleEndian.PutUint16(buf[4:6], 0x0200) // wRevision = WIN_CERT_REVISION_2_0
	binary.LittleEndian.PutUint16(buf[6:8], 0x0002) // wCertificateType = WIN_CERT_TYPE_PKCS_SIGNED_DATA
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
	// SpcPeImageData
	peImageData := spcPeImageData{
		Flags: asn1.BitString{Bytes: []byte{0}, BitLength: 0},
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
	// 构造 authenticated attributes
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

	// 3. MessageDigest = SHA-256(indirectData DER)
	// signtool /ds 验证此值，必须与 indirectData 内容的 hash 匹配
	msgDigestBytes := sha256.Sum256(indirectData)
	msgDigestAttr, err := buildAttr(oidMessageDigest, asn1.RawValue{Tag: asn1.TagOctetString, Bytes: msgDigestBytes[:]})
	if err != nil {
		return nil, err
	}

	// 将三个 attribute 组合成 SET
	authAttrsBytes := append(append(contentTypeAttr, opusInfoAttr...), msgDigestAttr...)

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
			Algorithm:  oidSHA256WithRSA,
			Parameters: asn1.RawValue{Tag: asn1.TagNull},
		},
		EncryptedDigest: []byte{}, // 空签名值 — 由 signtool /ds 填充
	}

	return asn1.Marshal(si)
}

func buildSignedData(cert *x509.Certificate, indirectData []byte, signerInfoDER []byte) ([]byte, error) {
	// ContentInfo for SpcIndirectDataContent
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
