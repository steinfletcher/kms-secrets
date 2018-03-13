package compress

import (
	"testing"
	"github.com/stretchr/testify/assert"
)

func TestGzipCompressor(t *testing.T) {
	data := []byte("some data")
	compressor := NewGzipCompressor()

	err, encoded := compressor.Encode(data)
	if err != nil {
		t.Fatal(err)
	}

	err, decoded := compressor.Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, data, decoded)
}
