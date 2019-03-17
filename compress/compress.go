package compress

import (
	"bytes"
	"compress/gzip"
	"io/ioutil"
)

type Compressor interface {
	Encode(content []byte) (error, []byte)
	Decode(content []byte) (error, []byte)
}

func NewGzipCompressor() Compressor {
	return &GzipCompressor{}
}

type GzipCompressor struct{}

func (c *GzipCompressor) Encode(content []byte) (error, []byte) {
	var buffer bytes.Buffer
	writer, err := gzip.NewWriterLevel(&buffer, gzip.BestCompression)
	if err != nil {
		return err, nil
	}

	_, err = writer.Write(content)
	if err != nil {
		return err, nil
	}

	writer.Close()
	return nil, buffer.Bytes()
}

func (c *GzipCompressor) Decode(content []byte) (error, []byte) {
	reader, err := gzip.NewReader(bytes.NewBuffer(content))
	if err != nil {
		return err, nil
	}

	data, err := ioutil.ReadAll(reader)
	if err != nil {
		return err, nil
	}

	reader.Close()
	return nil, data
}
