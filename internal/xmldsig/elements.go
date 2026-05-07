package xmldsig

import (
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"

	"github.com/beevik/etree"
)

const (
	DSigNS      = "http://www.w3.org/2000/09/xmldsig#"
	IncC14NAlgo = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
	ExcC14NAlgo = "http://www.w3.org/2001/10/xml-exc-c14n#"
	RSASha256   = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	Sha256Algo  = "http://www.w3.org/2001/04/xmlenc#sha256"
	EnvSigAlgo  = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
)

// buildSignedInfo 构造 <SignedInfo> 元素（无命名空间前缀，使用 Inclusive C14N）
func buildSignedInfo(digestValue string) *etree.Element {
	si := etree.NewElement("SignedInfo")
	si.CreateAttr("xmlns", DSigNS)

	cm := si.CreateElement("CanonicalizationMethod")
	cm.CreateAttr("Algorithm", IncC14NAlgo)

	sm := si.CreateElement("SignatureMethod")
	sm.CreateAttr("Algorithm", RSASha256)

	ref := si.CreateElement("Reference")
	ref.CreateAttr("URI", "")

	transforms := ref.CreateElement("Transforms")
	t := transforms.CreateElement("Transform")
	t.CreateAttr("Algorithm", EnvSigAlgo)

	dm := ref.CreateElement("DigestMethod")
	dm.CreateAttr("Algorithm", Sha256Algo)

	dv := ref.CreateElement("DigestValue")
	dv.SetText(digestValue)

	return si
}

// buildSignatureElement 组装完整的 <Signature>（无命名空间前缀）
func buildSignatureElement(signedInfo *etree.Element, signatureB64 string, certDER []byte, chainDERs [][]byte) *etree.Element {
	sig := etree.NewElement("Signature")
	sig.CreateAttr("xmlns", DSigNS)

	// 复制 SignedInfo，去掉独立的 xmlns（父元素已声明）
	siCopy := signedInfo.Copy()
	siCopy.RemoveAttr("xmlns")
	sig.AddChild(siCopy)

	// <SignatureValue>
	sv := sig.CreateElement("SignatureValue")
	sv.SetText(signatureB64)

	// <KeyInfo>
	ki := sig.CreateElement("KeyInfo")
	buildKeyInfo(ki, certDER)

	// <Object> with issuer certificate chain
	if len(chainDERs) > 0 {
		buildObject(sig, chainDERs)
	}

	return sig
}

// buildKeyInfo 构造 KeyInfo 内容：RSAKeyValue + X509Data
func buildKeyInfo(ki *etree.Element, certDER []byte) {
	cert, err := x509.ParseCertificate(certDER)
	if err == nil {
		if rsaPub, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			// <KeyValue><RSAKeyValue>
			kv := ki.CreateElement("KeyValue")
			rsaKV := kv.CreateElement("RSAKeyValue")

			modElem := rsaKV.CreateElement("Modulus")
			modElem.SetText(base64.StdEncoding.EncodeToString(rsaPub.N.Bytes()))

			expElem := rsaKV.CreateElement("Exponent")
			expElem.SetText(base64.StdEncoding.EncodeToString(big.NewInt(int64(rsaPub.E)).Bytes()))
		}

		// <X509Data>
		x509data := ki.CreateElement("X509Data")

		// <X509IssuerSerial>
		issuerSerial := x509data.CreateElement("X509IssuerSerial")
		issuerName := issuerSerial.CreateElement("X509IssuerName")
		issuerName.SetText(formatX509Name(cert.Issuer))
		serialNum := issuerSerial.CreateElement("X509SerialNumber")
		serialNum.SetText(cert.SerialNumber.String())

		// <X509SubjectName>
		subjectName := x509data.CreateElement("X509SubjectName")
		subjectName.SetText(formatX509Name(cert.Subject))

		// <X509Certificate>
		x509cert := x509data.CreateElement("X509Certificate")
		x509cert.SetText(base64.StdEncoding.EncodeToString(certDER))
	} else {
		// fallback: 只放证书
		x509data := ki.CreateElement("X509Data")
		x509cert := x509data.CreateElement("X509Certificate")
		x509cert.SetText(base64.StdEncoding.EncodeToString(certDER))
	}
}

// buildObject 构造 <Object><SignatureProperties> 包含 issuer 证书链
func buildObject(sig *etree.Element, chainDERs [][]byte) {
	obj := sig.CreateElement("Object")
	sigProps := obj.CreateElement("SignatureProperties")
	sigProp := sigProps.CreateElement("SignatureProperty")
	sigProp.CreateAttr("Target", DSigNS+"signatureProperties")

	for _, der := range chainDERs {
		issuerCert := sigProp.CreateElement("issuerCertificate")
		issuerCert.SetText(base64.StdEncoding.EncodeToString(der))
	}
}

// formatX509Name 格式化 X.509 DN 为 .NET 风格
// 例: CN=DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1, O="DigiCert, Inc.", C=US
func formatX509Name(name pkix.Name) string {
	var parts []string

	// .NET 风格的 OID 到短名映射
	oidNames := map[string]string{
		"2.5.4.3":  "CN",
		"2.5.4.10": "O",
		"2.5.4.11": "OU",
		"2.5.4.6":  "C",
		"2.5.4.8":  "S",
		"2.5.4.7":  "L",
	}

	// 按 RDN 序列逆序输出（X.509 DN 从叶到根）
	for i := len(name.Names) - 1; i >= 0; i-- {
		atv := name.Names[i]
		oid := atv.Type.String()
		shortName, ok := oidNames[oid]
		if !ok {
			shortName = oid
		}
		value := fmt.Sprintf("%v", atv.Value)

		// 值中包含逗号时用引号包裹
		if strings.Contains(value, ",") {
			value = `"` + value + `"`
		}

		parts = append(parts, shortName+"="+value)
	}

	return strings.Join(parts, ", ")
}

// removeExistingSignatures 从根元素移除已有的 <Signature> 元素
// 用于 enveloped-signature transform
func removeExistingSignatures(root *etree.Element) {
	var toRemove []*etree.Element
	for _, child := range root.ChildElements() {
		if child.Tag == "Signature" {
			ns := child.NamespaceURI()
			if ns == DSigNS || child.Space == "ds" {
				toRemove = append(toRemove, child)
			}
		}
	}
	for _, elem := range toRemove {
		root.RemoveChild(elem)
	}
}
