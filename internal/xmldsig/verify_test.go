package xmldsig

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"testing"
	"time"
)

// generateSelfSignedCert 生成用于测试的自签名 RSA 证书，返回 (certDER, privateKey)
func generateSelfSignedCert(t *testing.T) ([]byte, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test Signer",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return certDER, key
}

func TestVerifyXML_Valid(t *testing.T) {
	certDER, key := generateSelfSignedCert(t)

	xmlInput := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<order>
  <item>Widget</item>
  <quantity>100</quantity>
</order>`)

	signed, err := SignXML(xmlInput, certDER, mockSignFunc(key))
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	result, err := VerifyXML(signed)
	if err != nil {
		t.Fatalf("verify returned error: %v", err)
	}
	if !result.Valid {
		t.Fatal("expected Valid=true")
	}
	if result.SubjectCN != "Test Signer" {
		t.Errorf("expected SubjectCN 'Test Signer', got %q", result.SubjectCN)
	}
}

func TestVerifyXML_TamperedContent(t *testing.T) {
	certDER, key := generateSelfSignedCert(t)

	xmlInput := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<order>
  <item>Widget</item>
  <quantity>100</quantity>
</order>`)

	signed, err := SignXML(xmlInput, certDER, mockSignFunc(key))
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	// 篡改内容：把 100 改成 999
	tampered := make([]byte, 0, len(signed))
	for i := 0; i < len(signed); i++ {
		if i+3 <= len(signed) && string(signed[i:i+3]) == "100" {
			tampered = append(tampered, []byte("999")...)
			i += 2
		} else {
			tampered = append(tampered, signed[i])
		}
	}

	_, err = VerifyXML(tampered)
	if err == nil {
		t.Fatal("expected error for tampered content, got nil")
	}
}

func TestVerifyXML_TamperedSignatureValue(t *testing.T) {
	certDER, key := generateSelfSignedCert(t)
	_ = key

	xmlInput := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<order>
  <item>Widget</item>
</order>`)

	// 用正确的 certDER 但用错误私钥签名 SignedInfo → SignatureValue 与证书公钥不匹配
	badKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	badSignFunc := func(digestHex string) (string, error) {
		fakeSig, _ := rsa.SignPKCS1v15(rand.Reader, badKey, crypto.SHA256, make([]byte, 32))
		return base64.StdEncoding.EncodeToString(fakeSig), nil
	}
	signedBad, err := SignXML(xmlInput, certDER, badSignFunc)
	if err != nil {
		t.Fatalf("sign with bad key failed: %v", err)
	}

	_, err = VerifyXML(signedBad)
	if err == nil {
		t.Fatal("expected error for bad signature, got nil")
	}
}

func TestVerifyXML_NoSignature(t *testing.T) {
	xmlInput := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<order>
  <item>Widget</item>
</order>`)

	_, err := VerifyXML(xmlInput)
	if err == nil {
		t.Fatal("expected error for unsigned XML, got nil")
	}
}

func TestVerifyXML_InvalidXML(t *testing.T) {
	_, err := VerifyXML([]byte("not xml at all"))
	if err == nil {
		t.Fatal("expected error for invalid XML, got nil")
	}
}

func TestVerifyXML_WithNamespaces(t *testing.T) {
	certDER, key := generateSelfSignedCert(t)

	xmlInput := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<ns:order xmlns:ns="http://example.com/order">
  <ns:item>Widget</ns:item>
  <ns:quantity>100</ns:quantity>
</ns:order>`)

	signed, err := SignXML(xmlInput, certDER, mockSignFunc(key))
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	result, err := VerifyXML(signed)
	if err != nil {
		t.Fatalf("verify returned error: %v", err)
	}
	if !result.Valid {
		t.Fatal("expected Valid=true for namespaced XML")
	}
}
