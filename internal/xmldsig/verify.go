package xmldsig

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/beevik/etree"
)

// VerifyResult 验签结果
type VerifyResult struct {
	// Valid 表示签名数学上验证通过（digest 和 signature 都正确）
	Valid bool
	// Certificate 从 XML 中提取到的签名证书（可能为 nil，若 XML 中未嵌入证书）
	Certificate *x509.Certificate
	// SubjectCN 证书 CommonName，方便打印
	SubjectCN string
	// NotBefore / NotAfter 直接暴露给调用方
	NotBefore string
	NotAfter  string
}

// VerifyXML 验证 XMLDSIG Enveloped 签名
//
// 流程：
//  1. 从 XML 中提取 <ds:Signature>
//  2. 从 <ds:X509Certificate> 解析公钥
//  3. 按签名时相同的 c14n 流程重算 Reference Digest，与 <ds:DigestValue> 比对
//  4. 按签名时相同的 c14n 流程重算 SignedInfo Digest，用公钥验证 <ds:SignatureValue>
func VerifyXML(xmlBytes []byte) (*VerifyResult, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlBytes); err != nil {
		return nil, fmt.Errorf("parse XML: %w", err)
	}
	root := doc.Root()
	if root == nil {
		return nil, fmt.Errorf("XML document has no root element")
	}

	// ─── 1. 找到 <ds:Signature> ─────────────────────────────────────────────
	sigElem := findSignature(root)
	if sigElem == nil {
		return nil, fmt.Errorf("no ds:Signature element found")
	}

	// ─── 2. 提取 X509Certificate → 公钥 ────────────────────────────────────
	certDER, err := extractCertDER(sigElem)
	if err != nil {
		return nil, fmt.Errorf("extract certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	rsaPub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("certificate public key is not RSA")
	}

	// ─── 3. 验证 Reference Digest ────────────────────────────────────────────
	// 3a. 提取 <ds:DigestValue>
	expectedDigest, err := extractText(sigElem, ".//ds:DigestValue", ".//DigestValue")
	if err != nil {
		return nil, fmt.Errorf("read DigestValue: %w", err)
	}
	expectedDigestBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(expectedDigest))
	if err != nil {
		return nil, fmt.Errorf("decode DigestValue: %w", err)
	}

	// 3b. 重算内容 digest：移除签名节点后对 root 做 Exc-C14N
	rootCopy := root.Copy()
	removeExistingSignatures(rootCopy)
	contentC14N, err := exclusiveC14NCopy(rootCopy)
	if err != nil {
		return nil, fmt.Errorf("c14n content: %w", err)
	}
	actualContentDigest := sha256.Sum256(contentC14N)

	if !bytesEqual(actualContentDigest[:], expectedDigestBytes) {
		return &VerifyResult{Valid: false, Certificate: cert}, fmt.Errorf("digest mismatch: document has been tampered")
	}

	// ─── 4. 验证 SignatureValue ──────────────────────────────────────────────
	// 4a. 提取 <ds:SignatureValue>
	sigValueB64, err := extractText(sigElem, ".//ds:SignatureValue", ".//SignatureValue")
	if err != nil {
		return nil, fmt.Errorf("read SignatureValue: %w", err)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sigValueB64))
	if err != nil {
		return nil, fmt.Errorf("decode SignatureValue: %w", err)
	}

	// 4b. 重建 <ds:SignedInfo> 节点（从现有 XML 提取，添加回 xmlns:ds）
	signedInfoElem := findSignedInfo(sigElem)
	if signedInfoElem == nil {
		return nil, fmt.Errorf("no SignedInfo element found")
	}
	// 确保 SignedInfo 携带 xmlns:ds 以便 c14n 正确处理
	siForC14N := signedInfoElem.Copy()
	if siForC14N.SelectAttr("xmlns:ds") == nil {
		siForC14N.CreateAttr("xmlns:ds", DSigNS)
	}
	signedInfoC14N, err := exclusiveC14N(siForC14N)
	if err != nil {
		return nil, fmt.Errorf("c14n signedinfo: %w", err)
	}
	signedInfoDigest := sha256.Sum256(signedInfoC14N)

	if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, signedInfoDigest[:], sigBytes); err != nil {
		return &VerifyResult{Valid: false, Certificate: cert}, fmt.Errorf("signature verification failed: %w", err)
	}

	result := &VerifyResult{
		Valid:       true,
		Certificate: cert,
		SubjectCN:   cert.Subject.CommonName,
		NotBefore:   cert.NotBefore.UTC().Format("2006-01-02 15:04:05 UTC"),
		NotAfter:    cert.NotAfter.UTC().Format("2006-01-02 15:04:05 UTC"),
	}
	return result, nil
}

// ─── helpers ────────────────────────────────────────────────────────────────

func findSignature(root *etree.Element) *etree.Element {
	// 先找带前缀的
	if e := root.FindElement(".//ds:Signature"); e != nil {
		return e
	}
	// 再找无前缀但在 DSigNS 命名空间的
	for _, e := range root.FindElements(".//Signature") {
		if e.NamespaceURI() == DSigNS {
			return e
		}
	}
	return nil
}

func findSignedInfo(sig *etree.Element) *etree.Element {
	if e := sig.FindElement("ds:SignedInfo"); e != nil {
		return e
	}
	return sig.FindElement("SignedInfo")
}

func extractCertDER(sig *etree.Element) ([]byte, error) {
	b64, err := extractText(sig, ".//ds:X509Certificate", ".//X509Certificate")
	if err != nil {
		return nil, err
	}
	// 去掉换行和空格（PEM 风格的 base64 可能带换行）
	b64 = strings.ReplaceAll(b64, "\n", "")
	b64 = strings.ReplaceAll(b64, "\r", "")
	b64 = strings.TrimSpace(b64)
	return base64.StdEncoding.DecodeString(b64)
}

func extractText(elem *etree.Element, path1, path2 string) (string, error) {
	e := elem.FindElement(path1)
	if e == nil {
		e = elem.FindElement(path2)
	}
	if e == nil {
		return "", fmt.Errorf("element not found: %s", path1)
	}
	return e.Text(), nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
