package metadata

import (
  "crypto/sha256"
  
  "golang.org/x/sys/unix"
)

const (
  PolicyDescriptorLenV1 = 2 * unix.FSCRYPT_KEY_DESCRIPTOR_SIZE
  ProtectorDescriptorLen = PolicyDescriptorLenV1

  PolicyDescriptorLenV2 = 2 * unix.FSCRYPT_KEY_IDENTIFIER_SIZE

  InternalKeyLen = 32
  IVLen = 16
  SaltLen = 16

  HMACLen = sha256.Size
  
  PolicyKeyLen = unix.FSCRYPT_MAX_KEY_SIZE
)

var (
  DefaultOptions = &EncryptionOptions {
    Padding: 32,
    Contents: EncryptionOptions_AES_256_XTS,
    Filenames: EncryptionOptions_AES_256_CTS,
    PolicyVersion: 1
  }
  DefaultSource = SourceType_custom_passphrase
)
