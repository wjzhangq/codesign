package handler

import (
	"io"

	"github.com/klauspost/compress/zstd"
)

// zstdReadCloser 包装 zstd.Decoder 实现 io.ReadCloser
type zstdReadCloser struct {
	decoder *zstd.Decoder
}

func (z *zstdReadCloser) Read(p []byte) (n int, err error) {
	return z.decoder.Read(p)
}

func (z *zstdReadCloser) Close() error {
	z.decoder.Close()
	return nil
}

// newZstdReader 创建 zstd 解压 reader
func newZstdReader(r io.Reader) (io.ReadCloser, error) {
	decoder, err := zstd.NewReader(r)
	if err != nil {
		return nil, err
	}
	return &zstdReadCloser{decoder: decoder}, nil
}
