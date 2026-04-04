package xmldsig

import (
	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// exclusiveC14N 对 etree.Element 执行 Exclusive Canonical XML 1.0 序列化
// 注意: 此函数会修改传入元素，调用方应传入副本
func exclusiveC14N(elem *etree.Element) ([]byte, error) {
	c14n := dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	return c14n.Canonicalize(elem)
}

// exclusiveC14NCopy 对 etree.Element 的副本执行 Exclusive C14N，不修改原始元素
func exclusiveC14NCopy(elem *etree.Element) ([]byte, error) {
	return exclusiveC14N(elem.Copy())
}
