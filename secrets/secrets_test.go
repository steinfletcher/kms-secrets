package secrets

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestDetermineOriginalFileNameGzip(t *testing.T) {
	encFileName := "data.txt.gz.enc"

	orig := originalFileName(encFileName)

	assert.Equal(t, "data.txt", orig)
}

func TestDetermineOriginalFileNameSplit(t *testing.T) {
	encFileName := "cert.pem.1of3.enc"

	orig := originalFileName(encFileName)

	assert.Equal(t, "cert.pem", orig)
}

func TestDetermineOriginalFileNameEnc(t *testing.T) {
	encFileName := "secrets.enc"

	orig := originalFileName(encFileName)

	assert.Equal(t, "secrets", orig)
}

func TestFindSplitNumber(t *testing.T) {
	encFileName := "secrets.json.31of41.enc"

	orig := findSplitNumber(encFileName)

	assert.Equal(t, 31, orig)
}

func TestChunkContent(t *testing.T) {
	content := []byte("abcdefghij")

	chunked := chunk(content, 2)

	assert.Equal(t, 5, len(chunked))
	assert.Equal(t, "ab", string(chunked[0]))
	assert.Equal(t, "ij", string(chunked[4]))
}
