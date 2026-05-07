package xmldsig

import (
	"bytes"
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
	Valid       bool
	Certificate *x509.Certificate
	SubjectCN  string
	NotBefore  string
	NotAfter   string
}

// VerifyXML 验证 XMLDSIG Enveloped 签名
func VerifyXML(xmlBytes []byte) (*VerifyResult, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlBytes); err != nil {
		return nil, fmt.Errorf("parse XML: %w", err)
	}
	root := doc.Root()
	if root == nil {
		return nil, fmt.Errorf("XML document has no root element")
	}

	// ─── 1. 找到 <Signature> ─────────────────────────────────────────────
	sigElem := findSignature(root)
	if sigElem == nil {
		return nil, fmt.Errorf("no Signature element found")
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

	// ─── 检测 C14N 算法 ──────────────────────────────────────────────────
	signedInfoElem := findSignedInfo(sigElem)
	if signedInfoElem == nil {
		return nil, fmt.Errorf("no SignedInfo element found")
	}
	useExcC14N := detectExclusiveC14N(signedInfoElem)

	// ─── 3. 验证 Reference Digest ────────────────────────────────────────────
	expectedDigest, err := extractText(sigElem, ".//ds:DigestValue", ".//DigestValue")
	if err != nil {
		return nil, fmt.Errorf("read DigestValue: %w", err)
	}
	expectedDigestBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(expectedDigest))
	if err != nil {
		return nil, fmt.Errorf("decode DigestValue: %w", err)
	}

	rootCopy := root.Copy()
	removeExistingSignatures(rootCopy)

	var contentC14N []byte
	if useExcC14N {
		contentC14N, err = exclusiveC14NCopy(rootCopy)
	} else {
		contentC14N, err = inclusiveC14NCopy(rootCopy)
	}
	if err != nil {
		return nil, fmt.Errorf("c14n content: %w", err)
	}
	actualContentDigest := sha256.Sum256(contentC14N)

	if !bytes.Equal(actualContentDigest[:], expectedDigestBytes) {
		return &VerifyResult{Valid: false, Certificate: cert}, fmt.Errorf("digest mismatch: document has been tampered")
	}

	// ─── 4. 验证 SignatureValue ──────────────────────────────────────────────
	sigValueB64, err := extractText(sigElem, ".//ds:SignatureValue", ".//SignatureValue")
	if err != nil {
		return nil, fmt.Errorf("read SignatureValue: %w", err)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sigValueB64))
	if err != nil {
		return nil, fmt.Errorf("decode SignatureValue: %w", err)
	}

	siForC14N := signedInfoElem.Copy()
	var signedInfoC14N []byte
	if useExcC14N {
		if siForC14N.SelectAttr("xmlns:ds") == nil {
			siForC14N.CreateAttr("xmlns:ds", DSigNS)
		}
		signedInfoC14N, err = exclusiveC14N(siForC14N)
	} else {
		if siForC14N.SelectAttr("xmlns") == nil && siForC14N.SelectAttr("xmlns:ds") == nil {
			siForC14N.CreateAttr("xmlns", DSigNS)
		}
		signedInfoC14N, err = inclusiveC14N(siForC14N)
	}
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

// detectExclusiveC14N 检测 SignedInfo 中的 CanonicalizationMethod 是否为 Exclusive C14N
func detectExclusiveC14N(signedInfo *etree.Element) bool {
	paths := []string{
		"ds:CanonicalizationMethod",
		"CanonicalizationMethod",
	}
	for _, p := range paths {
		if cm := signedInfo.FindElement(p); cm != nil {
			algo := cm.SelectAttrValue("Algorithm", "")
			return algo == ExcC14NAlgo
		}
	}
	return false
}

func findSignature(root *etree.Element) *etree.Element {
	if e := root.FindElement(".//ds:Signature"); e != nil {
		return e
	}
	for _, e := range root.FindElements(".//Signature") {
		if e.NamespaceURI() == DSigNS {
			return e
		}
	}
	for _, e := range root.ChildElements() {
		if e.Tag == "Signature" {
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
