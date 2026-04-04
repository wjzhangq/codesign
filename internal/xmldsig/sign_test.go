package xmldsig

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/beevik/etree"
)

// mockSignFunc 使用本地 RSA 私钥签名，验证流程正确性
func mockSignFunc(key *rsa.PrivateKey) func(string) (string, error) {
	return func(digestHex string) (string, error) {
		digest, err := hex.DecodeString(digestHex)
		if err != nil {
			return "", err
		}
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest)
		if err != nil {
			return "", err
		}
		return base64.StdEncoding.EncodeToString(sig), nil
	}
}

func TestSignXML_Structure(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	// 简单使用空 certDER 进行结构测试
	certDER := []byte("test-cert-der")

	xmlInput := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<order>
  <item>Widget</item>
  <quantity>100</quantity>
</order>`)

	out, err := SignXML(xmlInput, certDER, mockSignFunc(key))
	if err != nil {
		t.Fatalf("SignXML failed: %v", err)
	}

	// 解析输出
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(out); err != nil {
		t.Fatalf("output XML parse failed: %v", err)
	}
	root := doc.Root()

	// 验证 <ds:Signature> 存在
	sig := root.FindElement("//ds:Signature")
	if sig == nil {
		// 尝试无前缀
		sig = root.FindElement("//Signature")
	}
	if sig == nil {
		t.Fatal("ds:Signature element not found in output")
	}

	// 验证 SignatureValue 非空
	sv := sig.FindElement(".//ds:SignatureValue")
	if sv == nil {
		sv = sig.FindElement(".//SignatureValue")
	}
	if sv == nil || strings.TrimSpace(sv.Text()) == "" {
		t.Fatal("SignatureValue is missing or empty")
	}

	// 验证 DigestValue 非空
	dv := sig.FindElement(".//ds:DigestValue")
	if dv == nil {
		dv = sig.FindElement(".//DigestValue")
	}
	if dv == nil || strings.TrimSpace(dv.Text()) == "" {
		t.Fatal("DigestValue is missing or empty")
	}

	// 验证 X509Certificate 非空
	cert := sig.FindElement(".//ds:X509Certificate")
	if cert == nil {
		cert = sig.FindElement(".//X509Certificate")
	}
	if cert == nil || strings.TrimSpace(cert.Text()) == "" {
		t.Fatal("X509Certificate is missing or empty")
	}
}

func TestSignXML_Idempotent(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	certDER := []byte("test-cert-der")

	xmlInput := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<order>
  <item>Widget</item>
</order>`)

	// 第一次签名
	signed1, err := SignXML(xmlInput, certDER, mockSignFunc(key))
	if err != nil {
		t.Fatalf("first sign failed: %v", err)
	}

	// 第二次签名（对已签名 XML 重签）
	key2, _ := rsa.GenerateKey(rand.Reader, 2048)
	signed2, err := SignXML(signed1, certDER, mockSignFunc(key2))
	if err != nil {
		t.Fatalf("second sign failed: %v", err)
	}

	// 验证只有一个 Signature
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(signed2); err != nil {
		t.Fatalf("parse re-signed XML: %v", err)
	}
	root := doc.Root()
	sigs := root.FindElements("//ds:Signature")
	if len(sigs) == 0 {
		sigs = root.FindElements("//Signature")
	}
	// 应该只有 1 个签名（旧签名被移除，新签名被添加）
	if len(sigs) != 1 {
		t.Fatalf("expected 1 Signature after re-sign, got %d", len(sigs))
	}
}

func TestSignXML_WithNamespaces(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	certDER := []byte("test-cert-der")

	xmlInput := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<ns:order xmlns:ns="http://example.com/order">
  <ns:item>Widget</ns:item>
  <ns:quantity>100</ns:quantity>
</ns:order>`)

	out, err := SignXML(xmlInput, certDER, mockSignFunc(key))
	if err != nil {
		t.Fatalf("SignXML with namespaces failed: %v", err)
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(out); err != nil {
		t.Fatalf("parse output: %v", err)
	}
	if doc.Root() == nil {
		t.Fatal("output has no root")
	}
}

func TestSignXML_EmptyXML(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	_, err := SignXML([]byte("not xml"), []byte("cert"), mockSignFunc(key))
	if err == nil {
		t.Fatal("expected error for invalid XML input")
	}
}

func TestSignXML_NoRoot(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	_, err := SignXML([]byte(`<?xml version="1.0"?>`), []byte("cert"), mockSignFunc(key))
	if err == nil {
		t.Fatal("expected error for XML with no root element")
	}
}

func TestRemoveExistingSignatures(t *testing.T) {
	xmlInput := `<root xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <data>hello</data>
  <ds:Signature><ds:SignatureValue>xxx</ds:SignatureValue></ds:Signature>
</root>`

	doc := etree.NewDocument()
	if err := doc.ReadFromString(xmlInput); err != nil {
		t.Fatal(err)
	}
	root := doc.Root()

	removeExistingSignatures(root)

	sigs := root.FindElements(".//ds:Signature")
	if len(sigs) != 0 {
		t.Fatalf("expected 0 signatures after removal, got %d", len(sigs))
	}
}
