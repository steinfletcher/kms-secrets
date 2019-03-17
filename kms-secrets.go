package main

import (
	"github.com/steinfletcher/kms-secrets/compress"
	"github.com/steinfletcher/kms-secrets/kms"
	"github.com/steinfletcher/kms-secrets/secrets"
	"gopkg.in/urfave/cli.v1"
	"os"
)

var (
	keyID, profile, region, filter, rootDir                     string
	keyIDFlag, profileFlag, regionFlag, filterFlag, rootDirFlag cli.Flag
)

func init() {
	keyIDFlag = cli.StringFlag{
		Name:        "k, key-id",
		Usage:       "KMS key ARN, alias or id",
		EnvVar:      "KMS_KEY_ID",
		Destination: &keyID,
	}
	regionFlag = cli.StringFlag{
		Name:        "r, region",
		Usage:       "AWS region",
		EnvVar:      "AWS_DEFAULT_REGION",
		Destination: &region,
	}
	profileFlag = cli.StringFlag{
		Name:        "p, profile",
		Usage:       "AWS profile",
		EnvVar:      "AWS_PROFILE",
		Destination: &profile,
	}
	filterFlag = cli.StringFlag{
		Name:        "f, filter",
		Usage:       "Filter files matching pattern",
		Value:       ".*",
		Destination: &filter,
	}
	rootDirFlag = cli.StringFlag{
		Name:        "d, dir",
		Usage:       "Sets the working directory for secrets encryption/decryption. Works recursively",
		Value:       "./",
		Destination: &rootDir,
	}
}

func main() {
	app := cli.NewApp()
	app.Name = "kms-secrets"
	app.Usage = "Encrypt and decrypt secrets using AWS KMS"

	app.Commands = []cli.Command{
		{
			Name:    "encrypt",
			Aliases: []string{"e"},
			Usage:   "Encrypt content",
			Flags:   []cli.Flag{keyIDFlag, profileFlag, regionFlag, filterFlag, rootDirFlag},
			Action: func(c *cli.Context) error {
				err := validateEncrypt()
				if err != nil {
					return err
				}

				err = context().Encrypt(rootDir)
				if err != nil {
					return cli.NewExitError(err, 1)
				}
				return nil
			},
		},
		{
			Name:    "decrypt",
			Aliases: []string{"d"},
			Usage:   "decrypt content ending in .enc",
			Flags:   []cli.Flag{profileFlag, regionFlag, filterFlag, rootDirFlag},
			Action: func(c *cli.Context) error {
				err := validateDecrypt()
				if err != nil {
					return err
				}

				err = context().Decrypt(rootDir)
				if err != nil {
					return cli.NewExitError(err, 1)
				}
				return nil
			},
		},
	}
	app.Version = "0.1.2"
	app.Run(os.Args)
}

func context() secrets.Secrets {
	compressor := compress.NewGzipCompressor()
	kmsCli := kms.NewKms(keyID, region, profile)
	return secrets.NewSecrets(kmsCli, compressor, filter)
}

func validateEncrypt() error {
	if len(keyID) == 0 {
		return cli.NewExitError("--key-id must be set", 1)
	}

	if len(region) == 0 {
		return cli.NewExitError("--region must be set", 1)
	}

	if len(profile) == 0 {
		return cli.NewExitError("--profile must be set", 1)
	}
	return nil
}

func validateDecrypt() error {
	if len(region) == 0 {
		return cli.NewExitError("--region must be set", 1)
	}

	if len(profile) == 0 {
		return cli.NewExitError("--profile must be set", 1)
	}
	return nil
}
