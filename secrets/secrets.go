package secrets

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/steinfletcher/kms-secrets/compress"
	"github.com/steinfletcher/kms-secrets/kms"
	"strconv"
	"log"
	"bytes"
	"sort"
)

const (
	green = "\x1b[32;1m"
	cyan  = "\x1b[36;1m"
)

type Secrets interface {
	Decrypt(rootDir string) error
	Encrypt(rootDir string) error
}

type KmsSecrets struct {
	kmsCli     kms.Kms
	compressor compress.Compressor
	filter     string
}

func NewSecrets(kmsCli kms.Kms, compressor compress.Compressor, filter string) Secrets {
	return &KmsSecrets{kmsCli, compressor, filter}
}

type Split struct {
	partNumber int
	content    []byte
}

func (ks *KmsSecrets) Encrypt(rootDir string) error {
	return filepath.Walk(rootDir, func(path string, f os.FileInfo, err error) error {

		if f.IsDir() || strings.HasPrefix(path, ".") || strings.HasSuffix(path, ".enc") {
			return nil
		}

		isMatch, _ := regexp.MatchString(ks.filter, path)
		if isMatch {
			bytes, err := ioutil.ReadFile(path)
			if err != nil {
				return err
			}

			if len(bytes) == 0 {
				fmt.Printf("%sSkipping empty file '%s'\n", green, path)
				return nil
			}

			strategy, compressedBytes := DetermineEncryptionStrategy(bytes)
			switch strategy {
			case SPLIT:
				err = ks.encryptSplit(path, bytes)
			case GZIP:
				err = ks.encrypt(path, path+".gz.enc", compressedBytes)
			default:
				err = ks.encrypt(path, path+".enc", bytes)
			}
			if err != nil {
				return err
			}
		}
		return nil
	})
}

func chunk(content []byte, size int) [][]byte {
	var chunk []byte
	chunks := make([][]byte, 0, len(content)/size+1)
	for len(content) >= size {
		chunk, content = content[:size], content[size:]
		chunks = append(chunks, chunk)
	}
	if len(content) > 0 {
		chunks = append(chunks, content[:])
	}
	return chunks
}

func (ks *KmsSecrets) encrypt(sourcePath string, targetPath string, content []byte) error {
	err, encrypted := ks.kmsCli.Encrypt(content)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(targetPath, encrypted, 0644)
	if err != nil {
		return err
	}
	fmt.Printf("%sEncrypted file '%s' -> '%s'\n", green, sourcePath, targetPath)
	return nil
}

func (ks *KmsSecrets) encryptSplit(path string, content []byte) error {
	//err, encoded := ks.compressor.Encode(content)
	//if err != nil {
	//	return err
	//}

	parts := chunk(content, ContentLimitBytes)
	for i, v := range parts {
		ks.encrypt(path, path+fmt.Sprintf(".%dof%d.enc", i+1, len(parts)), v)
	}
	return nil
}

func (ks *KmsSecrets) Decrypt(rootDir string) error {
	splits := make(map[string][]Split)

	err := filepath.Walk(rootDir, func(path string, f os.FileInfo, err error) error {
		if f.IsDir() || strings.HasPrefix(path, ".") {
			return nil
		}

		isMatch, _ := regexp.MatchString(ks.filter, path)
		if strings.HasSuffix(f.Name(), ".enc") && isMatch {

			encryptedSecret, err := ioutil.ReadFile(path)
			if err != nil {
				return err
			}

			strategy := DetermineDecryptionStrategy(f.Name())
			switch strategy {
			case SPLIT:
				err, split := ks.decryptSplit(path, encryptedSecret)
				if err != nil {
					return err
				}
				origName := originalFileName(path)
				splitNumber := findSplitNumber(path)
				splits[origName] = append(splits[origName], Split{partNumber: splitNumber, content: split})
			case GZIP:
				ks.decryptGzip(path, encryptedSecret)
			default:
				ks.decrypt(path, encryptedSecret)
			}
		}
		return nil
	})

	// join together splits
	if len(splits) > 0 {
		for k, split := range splits {

			// sort splits in order by part number
			var values []Split
			for _, v := range split {
				values = append(values, v)
			}

			sort.Slice(values, func(i, j int) bool {
				return values[i].partNumber < values[j].partNumber
			})

			// write out to file
			var buf bytes.Buffer
			for _, s := range values {
				buf.Write(s.content)
			}
			err = ioutil.WriteFile(k, buf.Bytes(), 0644)
		}

		if err != nil {
			return err
		}
	}

	return err
}

func (ks *KmsSecrets) decrypt(path string, content []byte) error {
	err, content := ks.kmsCli.Decrypt(content)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(originalFileName(path), content, 0644)
	if err != nil {
		return err
	}

	return nil
}

func (ks *KmsSecrets) decryptGzip(path string, content []byte) error {
	err, content := ks.kmsCli.Decrypt(content)
	if err != nil {
		return err
	}

	err, content = ks.compressor.Decode(content)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(originalFileName(path), content, 0644)
	if err != nil {
		return err
	}
	return nil
}

func (ks *KmsSecrets) decryptSplit(path string, content []byte) (error, []byte) {
	err, decrypted := ks.kmsCli.Decrypt(content)
	if err != nil {
		return err, nil
	}

	//err, decoded := ks.compressor.Decode(decrypted)
	//if err != nil {
	//	return err, nil
	//}

	return nil, decrypted
}

func originalFileName(path string) string {
	var orig = strings.TrimSuffix(path, ".gz.enc")
	orig = strings.TrimSuffix(orig, ".enc")

	splitRe := regexp.MustCompile(`^(.*)\.\d+of\d+$`)
	orig = splitRe.ReplaceAllString(orig, "$1")

	//fmt.Printf("%sDecrypting file '%s' -> '%s'\n", cyan, path, orig) // FIXME move out of here
	return orig
}

func findSplitNumber(path string) int {
	splitRe := regexp.MustCompile(`^.*\.(?P<first>\d+)of\d+\.enc$`)
	match := splitRe.FindStringSubmatch(path)
	i, err := strconv.Atoi(match[1])
	if err != nil {
		log.Fatal(err)
	}
	return i
}
