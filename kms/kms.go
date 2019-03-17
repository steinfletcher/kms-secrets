package kms

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
)

type Kms interface {
	Encrypt(content []byte) (error, []byte)
	Decrypt(content []byte) (error, []byte)
}

type KmsCli struct {
	keyId string
	cli   *kms.KMS
}

func NewKms(keyId string, region string, profile string) Kms {
	var kmsCli = kms.New(session.Must(session.NewSessionWithOptions(session.Options{
		Config:            aws.Config{Region: aws.String(region)},
		Profile:           profile,
		SharedConfigState: session.SharedConfigEnable,
	})))
	return &KmsCli{keyId: keyId, cli: kmsCli}
}

func (k *KmsCli) Encrypt(content []byte) (error, []byte) {
	params := &kms.EncryptInput{
		KeyId:     aws.String(k.keyId),
		Plaintext: content,
	}

	resp, err := k.cli.Encrypt(params)
	if err != nil {
		fmt.Println(err)
		return err, nil
	}

	return nil, resp.CiphertextBlob
}

func (k *KmsCli) Decrypt(content []byte) (error, []byte) {
	params := &kms.DecryptInput{
		CiphertextBlob: content,
	}

	resp, err := k.cli.Decrypt(params)
	if err != nil {
		return err, nil
	}

	return nil, resp.Plaintext
}
