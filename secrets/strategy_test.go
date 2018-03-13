package secrets

import (
	"io/ioutil"
	"math/rand"
	"testing"

	"github.com/steinfletcher/kms-secrets/compress"
	"github.com/stretchr/testify/assert"
)

func TestExceedsLimits(t *testing.T) {
	content, err := ioutil.ReadFile("../testdata/gzip.json")
	if err != nil {
		panic(err)
	}

	exceeds := exceedsFileSizeLimit(content)

	assert.True(t, exceeds)
}

func TestWithinLimits(t *testing.T) {
	content, err := ioutil.ReadFile("../testdata/default.json")
	if err != nil {
		panic(err)
	}

	exceeds := exceedsFileSizeLimit(content)

	assert.False(t, exceeds)
}

func TestDetermineDefaultEncryptionStrategy(t *testing.T) {
	content := randSeq(ContentLimitBytes)

	strategy, _ := DetermineEncryptionStrategy(content)

	assert.Equal(t, DEFAULT, strategy)
}

func TestDetermineGzipEncryptionStrategy(t *testing.T) {
	content := randSeq(ContentLimitBytes + 1)

	strategy, _ := DetermineEncryptionStrategy(content)

	assert.Equal(t, GZIP, strategy)
}

func TestDetermineSplitEncryptionStrategy(t *testing.T) {
	content := randSeq(50000)
	comp := compress.NewGzipCompressor()
	_, compressed := comp.Encode(content)
	assert.True(t, len(compressed) > ContentLimitBytes)

	strategy, _ := DetermineEncryptionStrategy(content)

	assert.Equal(t, SPLIT, strategy)
}

func TestDetermineDefaultDecryptionStrategy(t *testing.T) {
	fileName := "data.enc"

	strategy := DetermineDecryptionStrategy(fileName)

	assert.Equal(t, DEFAULT, strategy)
}

func TestDetermineGzipDecryptionStrategy(t *testing.T) {
	fileName := "data.gz.enc"

	strategy := DetermineDecryptionStrategy(fileName)

	assert.Equal(t, GZIP, strategy)
}

func TestDetermineSplitDecryptionStrategy(t *testing.T) {
	fileName := "data.1of2.enc"

	strategy := DetermineDecryptionStrategy(fileName)

	assert.Equal(t, SPLIT, strategy)
}

var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func randSeq(n int) []byte {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return []byte(string(b))
}
