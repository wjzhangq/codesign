package xmldsig

import (
	"encoding/base64"

	"github.com/beevik/etree"
)

const (
	DSigNS      = "http://www.w3.org/2000/09/xmldsig#"
	ExcC14NAlgo = "http://www.w3.org/2001/10/xml-exc-c14n#"
	RSASha256   = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	Sha256Algo  = "http://www.w3.org/2001/04/xmlenc#sha256"
	EnvSigAlgo  = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
)

// buildSignedInfo 构造 <ds:SignedInfo> 元素
func buildSignedInfo(digestValue string) *etree.Element {
	si := etree.NewElement("ds:SignedInfo")
	si.CreateAttr("xmlns:ds", DSigNS)

	cm := si.CreateElement("ds:CanonicalizationMethod")
	cm.CreateAttr("Algorithm", ExcC14NAlgo)

	sm := si.CreateElement("ds:SignatureMethod")
	sm.CreateAttr("Algorithm", RSASha256)

	ref := si.CreateElement("ds:Reference")
	ref.CreateAttr("URI", "")

	transforms := ref.CreateElement("ds:Transforms")
	t := transforms.CreateElement("ds:Transform")
	t.CreateAttr("Algorithm", EnvSigAlgo)

	dm := ref.CreateElement("ds:DigestMethod")
	dm.CreateAttr("Algorithm", Sha256Algo)

	dv := ref.CreateElement("ds:DigestValue")
	dv.SetText(digestValue)

	return si
}

// buildSignatureElement 组装完整的 <ds:Signature>
func buildSignatureElement(signedInfo *etree.Element, signatureB64 string, certDER []byte) *etree.Element {
	sig := etree.NewElement("ds:Signature")
	sig.CreateAttr("xmlns:ds", DSigNS)

	// 复制 SignedInfo，去掉独立的 xmlns:ds（父元素已声明）
	siCopy := signedInfo.Copy()
	siCopy.RemoveAttr("xmlns:ds")
	sig.AddChild(siCopy)

	// <SignatureValue>
	sv := sig.CreateElement("ds:SignatureValue")
	sv.SetText(signatureB64)

	// <KeyInfo>
	ki := sig.CreateElement("ds:KeyInfo")
	x509data := ki.CreateElement("ds:X509Data")
	x509cert := x509data.CreateElement("ds:X509Certificate")
	x509cert.SetText(base64.StdEncoding.EncodeToString(certDER))

	return sig
}

// removeExistingSignatures 从根元素移除已有的 <Signature> 元素
// 用于 enveloped-signature transform
func removeExistingSignatures(root *etree.Element) {
	var toRemove []*etree.Element
	for _, child := range root.ChildElements() {
		local := child.Tag
		if child.Space != "" {
			// 带前缀的标签，Tag 仅为本地名
		}
		if local == "Signature" {
			// 检查 namespace
			ns := child.NamespaceURI()
			if ns == DSigNS {
				toRemove = append(toRemove, child)
				continue
			}
			// 也检查带 ds: 前缀但 xmlns:ds 可能在父级声明的情况
			if child.Space == "ds" {
				toRemove = append(toRemove, child)
			}
		}
	}
	for _, elem := range toRemove {
		root.RemoveChild(elem)
	}
}
