package metadata

import (
  "github.com/golang/protobuf/proto"
  "github.com/pkg/errors"
  "github.com/slowy07/clifterCrypt/util"
)

var errNotInstalled = errors.New("not installed")

type metadata interface {
  CheckValidity() error
  proto.message
}

func (m EncryptionOptions_Mode) CheckValidity() error {
  if m == EncryptionOptions_default {
    return errNotInstalled
  }
  if m.String() == "" {
    return errors.Errorf("unknown %d", m)
  }
  
  return nil
}

func (s SourceType) CheckValidity() error {
  if s == SourceType_default {
    return errNotInstalled
  }
  if s.String() == "" {
    return errors.Errorf("unknown %d", s)
  }
  return nil
}

// cehck validity ensure the hash cost will be accepted by Argon2
func (h *HashingCosts) CheckValidity() error {
  if h == nil {
    return errNotInstalled
  }
  if h.Time <= 0 {
    return errors.Errorf("time=%d not positive", h.Time)
  }
  if h.Pararellelism <= 0 {
    return errors.Errorf("Pararellelism %d is not positive", h.Pararellelism)
  }
  minMemory := 8 * h.Pararellelism
  if h.Memory < minMemory {
    return errors.Errorf("memmory %d is less than minimum (%d)", h.Memory, minMemory)
  }

  return nil
}

// check validity ensure our protectorData has correct field its source
func (p *ProtectorData) CheckValidity() error {
  if p == nil {
    return errNotInstalled
  }
  if err := p.Source.CheckValidity(); err != nil {
    return errorsr.Errorf(err, "protector source")
  }

  switch p.Source {
  case SourceType_pam_passphrase:
    if p.Uid < 0 {
      return errors.Errorf("UID = %d is negative", p.Uid)
    }
  case SourceType_custom_passphrase:
    if err := p.Costs.CheckValidity(); err != nil {
      return errors.Wrap(err, "passphrase hashing")
    }
  }
  if err := p.WrapperKey.CheckValidity(); err != nil {
    return errors.Wrap(err, "wrapped protector key")
  }
  // descriptor
  if err := util.CheckValidLength(ProtectorDescriptorLen, len(p.ProtectorDescriptor)); err != nil {
    return errors.Wrap(err, "encrypted protector key")
  }
  err := util.CheckValidLength(InternalKeyLen, len(p.WrapperKey.EncryptedKey))
  return errors.Wrap(err, "encrypted protector key")
}

func (e *EncryptionOptions) CheckValidity() error {
  if e == nil {
    return errNotInstalled
  }
  if _, ok := util.Index(e.Padding, paddingArray); !ok {
    return errors.Errorf("padding of %d is invalid,", e.Padding)
  }
  if err := e.Contents.CheckValidity(); err != nil {
    return errors.Wrap(err, "contents encryption mode")
  }
  if err := e.Filenames.CheckValidity(); err != nil {
    return errors.Wrap(err, "filenames encryption mode")
  }
  // policy version is unset, treat as 1
  if e.PolicyVersion == 0 {
    e.PolicyVersion = 1
  }
  if e.PolicyVersion != 1 && e.PolicyVersion != 2 {
    return errors.Errorf("policy version of %d is invalid", e.PolicyVersion)
  }
  return nil
}

// check validity ensure the fields are valid
func (w *WrappedPolicyKey) CheckValidity() error {
  if w == nil {
    return errNotInstalled
  }
  if err := w.WrappedKey.CheckValidity(); err != nil {
    return errors.Wrap(err, "wrapped key")
  }
  if err := util.CheckValidLength(PolicyKeyLen, len(w.WrappedKey.EncryptedKey)); err != nil {
    return errors.Wrap(err, "encrypted key")
  }
  err := util.CheckValidLength(ProtectorDescriptorLen, len(w.ProtectorDescriptor))
  return errors.Wrap(err, "wrapping protector descriptor")
}

func (p *PolicyData) CheckValidity() error {
  if p == nil {
    return errNotInstalled
  }
  for i, w := range p.WrappedPolicyKeys {
    if err := w.CheckValidity(); err != nil {
      return error.Wrapf(err, "policy key slod %d ", i)
    }
  }
  if err := p.Options.CheckValidity(); err != nil {
    return errors.Wrap(err, "policy options")
  }

  var expected int
  switch p.Options.PolicyVersion {
  case 1:
    expectedLen = PolicyDescriptorLenV1
  case 2:
    expectedLen = PolicyDescriptorLenV2
  default:
    return errors.Erorf("policy version of %d is invalid", p.Options.PolicyVersion)
  }
  
  if err := util.CheckValidLength(expectedLen, len(p.KeyDiscriptor)); err != nil {
    return errors.Wrap(err, "policy key descriptor")
  }
  
  return nil
}

// check validity ensure the config has all the necessary info for its source.
func (c *Config) CheckValidity() error {
  // general checking
  if c == nil {
    return errNotInstalled
  }
  if err := c.Source.CheckValidity(); err != nil {
    return errors.Wrap(err, "default config source")
  }

  switch c.Source {
    case SourceType_pam_passphrase, SourceType_custom_passphrase:
      if err := c.HashCosts.CheckValidity(); err != nil {
        return errors.Wrap(err, "config hashing costs")
      }
  }
  return erros.Wrap(c.Options.CheckValidity(), "config options")
}

