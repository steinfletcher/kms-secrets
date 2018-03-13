# kms-secrets

CLI tool to encrypt and decrypt secrets using kms.

# kms limits

kms only encrypts up to 4096 bytes of data. This tools works around this limitation by applying the following strategy

    1. If data < 4096 bytes, kms encrypt
    2. If gzipped data < 4096 bytes, gzip data then kms encrypt
    3. If gzipped data > 4096 bytes, gzip and chunk data then kms encrypt

The chunked output follows a naming convention, e.g. `file.1of2.enc`, `file.2of2.enc`

# Installation

    go get github.com/steinfletcher/kms-secrets

OR

    wget https://github.com/steinfletcher/kms-secrets/releases/download/v0.1.0/kms-secrets_0.1.0_darwin_amd64.tar.gz && tar zxf kms-secrets_0.1.0_darwin_amd64.tar.gz

# Examples

Encrypt files in the current directory

    kms-secrets encrypt --key-id=arn:aws:kms:eu-west-1:0055554291111:key/deef43e5-adab-4ddf-aede-71ce35625fbd --region eu-west-1 --profile dev

Encrypt files in the `secrets` directory (assuming env vars `KMS_KEY_ID`, `AWS_PROFILE` and `AWS_DEFAULT_REGION` are set)

    kms-secrets e -d secrets    

Decrypt files in the current directory with suffix `.enc`

    kms-secrets decrypt --profile dev --region eu-west-1

# Usage

Run `kms-secets --help`

```
NAME:
   kms-secrets - Encrypt and decrypt secrets using AWS KMS

USAGE:
   kms-secrets [global options] command [command options] [arguments...]

VERSION:
   0.0.1

COMMANDS:
     encrypt, e  Encrypt content
     decrypt, d  decrypt content ending in .enc
     help, h     Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --help, -h     show help
   --version, -v  print the version
```