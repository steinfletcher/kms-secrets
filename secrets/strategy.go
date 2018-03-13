package secrets

import (
	"regexp"
	"strings"

	"github.com/steinfletcher/kms-secrets/compress"
)

type Strategy int

const ContentLimitBytes = 4096

var splitPattern *regexp.Regexp

const (
	DEFAULT Strategy = 1 + iota
	GZIP
	SPLIT
)

func init() {
	splitPattern = regexp.MustCompile(`^.*\.\d+of\d+\.enc$`)
}

func DetermineEncryptionStrategy(content []byte) (Strategy, []byte) {
	if !exceedsFileSizeLimit(content) {
		return DEFAULT, nil
	}

	comp := compress.NewGzipCompressor()
	err, compressedBytes := comp.Encode(content)
	if err != nil {
		panic(err)
	}
	if !exceedsFileSizeLimit(compressedBytes) {
		return GZIP, compressedBytes
	}

	return SPLIT, nil
}

func DetermineDecryptionStrategy(fileName string) Strategy {
	switch {
	case strings.HasSuffix(fileName, ".gz.enc"):
		return GZIP
	case splitPattern.MatchString(fileName):
		return SPLIT
	default:
		return DEFAULT
	}
}

func exceedsFileSizeLimit(content []byte) bool {
	return len(content) > ContentLimitBytes
}
