package xmldsig

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/beevik/etree"
)

// SignXML 对 XML 文档执行 XMLDSIG Enveloped 签名
//
// 参数:
//   - xmlBytes:  原始 XML 文档字节
//   - certDER:   公钥证书 DER 编码
//   - signFunc:  远程签名回调，接收 hex digest，返回 base64 签名值
//
// 返回签名后的完整 XML 文档字节
func SignXML(xmlBytes []byte, certDER []byte, signFunc func(digestHex string) (string, error)) ([]byte, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlBytes); err != nil {
		return nil, fmt.Errorf("parse XML: %w", err)
	}
	root := doc.Root()
	if root == nil {
		return nil, fmt.Errorf("XML document has no root element")
	}

	// ═══════════════════════════════════════
	// Step 1: 计算 Reference Digest
	// ═══════════════════════════════════════

	// 1a. enveloped-signature transform: 移除已有签名
	removeExistingSignatures(root)

	// 1b. Exclusive C14N（使用副本，不修改 root）
	contentC14N, err := exclusiveC14NCopy(root)
	if err != nil {
		return nil, fmt.Errorf("c14n content: %w", err)
	}

	// 1c. SHA-256
	contentDigest := sha256.Sum256(contentC14N)
	digestValue := base64.StdEncoding.EncodeToString(contentDigest[:])

	// ═══════════════════════════════════════
	// Step 2: 构造 SignedInfo 并计算 digest
	// ═══════════════════════════════════════

	signedInfoElem := buildSignedInfo(digestValue)

	// 2a. Exclusive C14N on SignedInfo（使用副本）
	signedInfoC14N, err := exclusiveC14NCopy(signedInfoElem)
	if err != nil {
		return nil, fmt.Errorf("c14n signedinfo: %w", err)
	}

	// 2b. SHA-256
	signedInfoDigest := sha256.Sum256(signedInfoC14N)
	signedInfoDigestHex := hex.EncodeToString(signedInfoDigest[:])

	// ═══════════════════════════════════════
	// Step 3: 远程签名
	// ═══════════════════════════════════════

	signatureB64, err := signFunc(signedInfoDigestHex)
	if err != nil {
		return nil, fmt.Errorf("remote sign: %w", err)
	}

	// ═══════════════════════════════════════
	// Step 4: 组装 Signature，嵌入文档
	// ═══════════════════════════════════════

	sigElem := buildSignatureElement(signedInfoElem, signatureB64, certDER)
	root.AddChild(sigElem)

	output, err := doc.WriteToBytes()
	if err != nil {
		return nil, fmt.Errorf("write XML: %w", err)
	}
	return output, nil
}
