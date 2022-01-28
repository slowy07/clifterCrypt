package metadata

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

// Specifies the method in which an outside secret is obtained for a Protector
type SourceType int32

const (
	SourceType_default           SourceType = 0
	SourceType_pam_passphrase    SourceType = 1
	SourceType_custom_passphrase SourceType = 2
	SourceType_raw_key           SourceType = 3
)

var SourceType_name = map[int32]string{
	0: "default",
	1: "pam_passphrase",
	2: "custom_passphrase",
	3: "raw_key",
}
var SourceType_value = map[string]int32{
	"default":           0,
	"pam_passphrase":    1,
	"custom_passphrase": 2,
	"raw_key":           3,
}

func (x SourceType) String() string {
	return proto.EnumName(SourceType_name, int32(x))
}
func (SourceType) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_metadata_20fa0d9b7a38c428, []int{0}
}

// Type of encryption; should match declarations of unix.FSCRYPT_MODE
type EncryptionOptions_Mode int32

const (
	EncryptionOptions_default     EncryptionOptions_Mode = 0
	EncryptionOptions_AES_256_XTS EncryptionOptions_Mode = 1
	EncryptionOptions_AES_256_GCM EncryptionOptions_Mode = 2
	EncryptionOptions_AES_256_CBC EncryptionOptions_Mode = 3
	EncryptionOptions_AES_256_CTS EncryptionOptions_Mode = 4
	EncryptionOptions_AES_128_CBC EncryptionOptions_Mode = 5
	EncryptionOptions_AES_128_CTS EncryptionOptions_Mode = 6
	EncryptionOptions_Adiantum    EncryptionOptions_Mode = 9
)

var EncryptionOptions_Mode_name = map[int32]string{
	0: "default",
	1: "AES_256_XTS",
	2: "AES_256_GCM",
	3: "AES_256_CBC",
	4: "AES_256_CTS",
	5: "AES_128_CBC",
	6: "AES_128_CTS",
	9: "Adiantum",
}
var EncryptionOptions_Mode_value = map[string]int32{
	"default":     0,
	"AES_256_XTS": 1,
	"AES_256_GCM": 2,
	"AES_256_CBC": 3,
	"AES_256_CTS": 4,
	"AES_128_CBC": 5,
	"AES_128_CTS": 6,
	"Adiantum":    9,
}

func (x EncryptionOptions_Mode) String() string {
	return proto.EnumName(EncryptionOptions_Mode_name, int32(x))
}
func (EncryptionOptions_Mode) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_metadata_20fa0d9b7a38c428, []int{3, 0}
}

// Cost parameters to be used in our hashing functions.
type HashingCosts struct {
	Time                 int64    `protobuf:"varint,2,opt,name=time,proto3" json:"time,omitempty"`
	Memory               int64    `protobuf:"varint,3,opt,name=memory,proto3" json:"memory,omitempty"`
	Parallelism          int64    `protobuf:"varint,4,opt,name=parallelism,proto3" json:"parallelism,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *HashingCosts) Reset()         { *m = HashingCosts{} }
func (m *HashingCosts) String() string { return proto.CompactTextString(m) }
func (*HashingCosts) ProtoMessage()    {}
func (*HashingCosts) Descriptor() ([]byte, []int) {
	return fileDescriptor_metadata_20fa0d9b7a38c428, []int{0}
}
func (m *HashingCosts) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_HashingCosts.Unmarshal(m, b)
}
func (m *HashingCosts) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_HashingCosts.Marshal(b, m, deterministic)
}
func (dst *HashingCosts) XXX_Merge(src proto.Message) {
	xxx_messageInfo_HashingCosts.Merge(dst, src)
}
func (m *HashingCosts) XXX_Size() int {
	return xxx_messageInfo_HashingCosts.Size(m)
}
func (m *HashingCosts) XXX_DiscardUnknown() {
	xxx_messageInfo_HashingCosts.DiscardUnknown(m)
}

var xxx_messageInfo_HashingCosts proto.InternalMessageInfo

func (m *HashingCosts) GetTime() int64 {
	if m != nil {
		return m.Time
	}
	return 0
}

func (m *HashingCosts) GetMemory() int64 {
	if m != nil {
		return m.Memory
	}
	return 0
}

func (m *HashingCosts) GetParallelism() int64 {
	if m != nil {
		return m.Parallelism
	}
	return 0
}

// This structure is used for our authenticated wrapping/unwrapping of keys.
type WrappedKeyData struct {
	IV                   []byte   `protobuf:"bytes,1,opt,name=IV,proto3" json:"IV,omitempty"`
	EncryptedKey         []byte   `protobuf:"bytes,2,opt,name=encrypted_key,json=encryptedKey,proto3" json:"encrypted_key,omitempty"`
	Hmac                 []byte   `protobuf:"bytes,3,opt,name=hmac,proto3" json:"hmac,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *WrappedKeyData) Reset()         { *m = WrappedKeyData{} }
func (m *WrappedKeyData) String() string { return proto.CompactTextString(m) }
func (*WrappedKeyData) ProtoMessage()    {}
func (*WrappedKeyData) Descriptor() ([]byte, []int) {
	return fileDescriptor_metadata_20fa0d9b7a38c428, []int{1}
}
func (m *WrappedKeyData) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_WrappedKeyData.Unmarshal(m, b)
}
func (m *WrappedKeyData) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_WrappedKeyData.Marshal(b, m, deterministic)
}
func (dst *WrappedKeyData) XXX_Merge(src proto.Message) {
	xxx_messageInfo_WrappedKeyData.Merge(dst, src)
}
func (m *WrappedKeyData) XXX_Size() int {
	return xxx_messageInfo_WrappedKeyData.Size(m)
}
func (m *WrappedKeyData) XXX_DiscardUnknown() {
	xxx_messageInfo_WrappedKeyData.DiscardUnknown(m)
}

var xxx_messageInfo_WrappedKeyData proto.InternalMessageInfo

func (m *WrappedKeyData) GetIV() []byte {
	if m != nil {
		return m.IV
	}
	return nil
}

func (m *WrappedKeyData) GetEncryptedKey() []byte {
	if m != nil {
		return m.EncryptedKey
	}
	return nil
}

func (m *WrappedKeyData) GetHmac() []byte {
	if m != nil {
		return m.Hmac
	}
	return nil
}

// The associated data for each protector
type ProtectorData struct {
	ProtectorDescriptor string     `protobuf:"bytes,1,opt,name=protector_descriptor,json=protectorDescriptor,proto3" json:"protector_descriptor,omitempty"`
	Source              SourceType `protobuf:"varint,2,opt,name=source,proto3,enum=metadata.SourceType" json:"source,omitempty"`
	// These are only used by some of the protector types
	Name                 string          `protobuf:"bytes,3,opt,name=name,proto3" json:"name,omitempty"`
	Costs                *HashingCosts   `protobuf:"bytes,4,opt,name=costs,proto3" json:"costs,omitempty"`
	Salt                 []byte          `protobuf:"bytes,5,opt,name=salt,proto3" json:"salt,omitempty"`
	Uid                  int64           `protobuf:"varint,6,opt,name=uid,proto3" json:"uid,omitempty"`
	WrappedKey           *WrappedKeyData `protobuf:"bytes,7,opt,name=wrapped_key,json=wrappedKey,proto3" json:"wrapped_key,omitempty"`
	XXX_NoUnkeyedLiteral struct{}        `json:"-"`
	XXX_unrecognized     []byte          `json:"-"`
	XXX_sizecache        int32           `json:"-"`
}

func (m *ProtectorData) Reset()         { *m = ProtectorData{} }
func (m *ProtectorData) String() string { return proto.CompactTextString(m) }
func (*ProtectorData) ProtoMessage()    {}
func (*ProtectorData) Descriptor() ([]byte, []int) {
	return fileDescriptor_metadata_20fa0d9b7a38c428, []int{2}
}
func (m *ProtectorData) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ProtectorData.Unmarshal(m, b)
}
func (m *ProtectorData) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ProtectorData.Marshal(b, m, deterministic)
}
func (dst *ProtectorData) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ProtectorData.Merge(dst, src)
}
func (m *ProtectorData) XXX_Size() int {
	return xxx_messageInfo_ProtectorData.Size(m)
}
func (m *ProtectorData) XXX_DiscardUnknown() {
	xxx_messageInfo_ProtectorData.DiscardUnknown(m)
}

var xxx_messageInfo_ProtectorData proto.InternalMessageInfo

func (m *ProtectorData) GetProtectorDescriptor() string {
	if m != nil {
		return m.ProtectorDescriptor
	}
	return ""
}

func (m *ProtectorData) GetSource() SourceType {
	if m != nil {
		return m.Source
	}
	return SourceType_default
}

func (m *ProtectorData) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *ProtectorData) GetCosts() *HashingCosts {
	if m != nil {
		return m.Costs
	}
	return nil
}

func (m *ProtectorData) GetSalt() []byte {
	if m != nil {
		return m.Salt
	}
	return nil
}

func (m *ProtectorData) GetUid() int64 {
	if m != nil {
		return m.Uid
	}
	return 0
}

func (m *ProtectorData) GetWrappedKey() *WrappedKeyData {
	if m != nil {
		return m.WrappedKey
	}
	return nil
}

// Encryption policy specifics, corresponds to the fscrypt_policy struct
type EncryptionOptions struct {
	Padding              int64                  `protobuf:"varint,1,opt,name=padding,proto3" json:"padding,omitempty"`
	Contents             EncryptionOptions_Mode `protobuf:"varint,2,opt,name=contents,proto3,enum=metadata.EncryptionOptions_Mode" json:"contents,omitempty"`
	Filenames            EncryptionOptions_Mode `protobuf:"varint,3,opt,name=filenames,proto3,enum=metadata.EncryptionOptions_Mode" json:"filenames,omitempty"`
	PolicyVersion        int64                  `protobuf:"varint,4,opt,name=policy_version,json=policyVersion,proto3" json:"policy_version,omitempty"`
	XXX_NoUnkeyedLiteral struct{}               `json:"-"`
	XXX_unrecognized     []byte                 `json:"-"`
	XXX_sizecache        int32                  `json:"-"`
}

func (m *EncryptionOptions) Reset()         { *m = EncryptionOptions{} }
func (m *EncryptionOptions) String() string { return proto.CompactTextString(m) }
func (*EncryptionOptions) ProtoMessage()    {}
func (*EncryptionOptions) Descriptor() ([]byte, []int) {
	return fileDescriptor_metadata_20fa0d9b7a38c428, []int{3}
}
func (m *EncryptionOptions) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_EncryptionOptions.Unmarshal(m, b)
}
func (m *EncryptionOptions) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_EncryptionOptions.Marshal(b, m, deterministic)
}
func (dst *EncryptionOptions) XXX_Merge(src proto.Message) {
	xxx_messageInfo_EncryptionOptions.Merge(dst, src)
}
func (m *EncryptionOptions) XXX_Size() int {
	return xxx_messageInfo_EncryptionOptions.Size(m)
}
func (m *EncryptionOptions) XXX_DiscardUnknown() {
	xxx_messageInfo_EncryptionOptions.DiscardUnknown(m)
}

var xxx_messageInfo_EncryptionOptions proto.InternalMessageInfo

func (m *EncryptionOptions) GetPadding() int64 {
	if m != nil {
		return m.Padding
	}
	return 0
}

func (m *EncryptionOptions) GetContents() EncryptionOptions_Mode {
	if m != nil {
		return m.Contents
	}
	return EncryptionOptions_default
}

func (m *EncryptionOptions) GetFilenames() EncryptionOptions_Mode {
	if m != nil {
		return m.Filenames
	}
	return EncryptionOptions_default
}

func (m *EncryptionOptions) GetPolicyVersion() int64 {
	if m != nil {
		return m.PolicyVersion
	}
	return 0
}

type WrappedPolicyKey struct {
	ProtectorDescriptor  string          `protobuf:"bytes,1,opt,name=protector_descriptor,json=protectorDescriptor,proto3" json:"protector_descriptor,omitempty"`
	WrappedKey           *WrappedKeyData `protobuf:"bytes,2,opt,name=wrapped_key,json=wrappedKey,proto3" json:"wrapped_key,omitempty"`
	XXX_NoUnkeyedLiteral struct{}        `json:"-"`
	XXX_unrecognized     []byte          `json:"-"`
	XXX_sizecache        int32           `json:"-"`
}

func (m *WrappedPolicyKey) Reset()         { *m = WrappedPolicyKey{} }
func (m *WrappedPolicyKey) String() string { return proto.CompactTextString(m) }
func (*WrappedPolicyKey) ProtoMessage()    {}
func (*WrappedPolicyKey) Descriptor() ([]byte, []int) {
	return fileDescriptor_metadata_20fa0d9b7a38c428, []int{4}
}
func (m *WrappedPolicyKey) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_WrappedPolicyKey.Unmarshal(m, b)
}
func (m *WrappedPolicyKey) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_WrappedPolicyKey.Marshal(b, m, deterministic)
}
func (dst *WrappedPolicyKey) XXX_Merge(src proto.Message) {
	xxx_messageInfo_WrappedPolicyKey.Merge(dst, src)
}
func (m *WrappedPolicyKey) XXX_Size() int {
	return xxx_messageInfo_WrappedPolicyKey.Size(m)
}
func (m *WrappedPolicyKey) XXX_DiscardUnknown() {
	xxx_messageInfo_WrappedPolicyKey.DiscardUnknown(m)
}

var xxx_messageInfo_WrappedPolicyKey proto.InternalMessageInfo

func (m *WrappedPolicyKey) GetProtectorDescriptor() string {
	if m != nil {
		return m.ProtectorDescriptor
	}
	return ""
}

func (m *WrappedPolicyKey) GetWrappedKey() *WrappedKeyData {
	if m != nil {
		return m.WrappedKey
	}
	return nil
}

// The associated data for each policy
type PolicyData struct {
	KeyDescriptor        string              `protobuf:"bytes,1,opt,name=key_descriptor,json=keyDescriptor,proto3" json:"key_descriptor,omitempty"`
	Options              *EncryptionOptions  `protobuf:"bytes,2,opt,name=options,proto3" json:"options,omitempty"`
	WrappedPolicyKeys    []*WrappedPolicyKey `protobuf:"bytes,3,rep,name=wrapped_policy_keys,json=wrappedPolicyKeys,proto3" json:"wrapped_policy_keys,omitempty"`
	XXX_NoUnkeyedLiteral struct{}            `json:"-"`
	XXX_unrecognized     []byte              `json:"-"`
	XXX_sizecache        int32               `json:"-"`
}

func (m *PolicyData) Reset()         { *m = PolicyData{} }
func (m *PolicyData) String() string { return proto.CompactTextString(m) }
func (*PolicyData) ProtoMessage()    {}
func (*PolicyData) Descriptor() ([]byte, []int) {
	return fileDescriptor_metadata_20fa0d9b7a38c428, []int{5}
}
func (m *PolicyData) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PolicyData.Unmarshal(m, b)
}
func (m *PolicyData) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PolicyData.Marshal(b, m, deterministic)
}
func (dst *PolicyData) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PolicyData.Merge(dst, src)
}
func (m *PolicyData) XXX_Size() int {
	return xxx_messageInfo_PolicyData.Size(m)
}
func (m *PolicyData) XXX_DiscardUnknown() {
	xxx_messageInfo_PolicyData.DiscardUnknown(m)
}

var xxx_messageInfo_PolicyData proto.InternalMessageInfo

func (m *PolicyData) GetKeyDescriptor() string {
	if m != nil {
		return m.KeyDescriptor
	}
	return ""
}

func (m *PolicyData) GetOptions() *EncryptionOptions {
	if m != nil {
		return m.Options
	}
	return nil
}

func (m *PolicyData) GetWrappedPolicyKeys() []*WrappedPolicyKey {
	if m != nil {
		return m.WrappedPolicyKeys
	}
	return nil
}

// Data stored in the config file
type Config struct {
	Source                    SourceType         `protobuf:"varint,1,opt,name=source,proto3,enum=metadata.SourceType" json:"source,omitempty"`
	HashCosts                 *HashingCosts      `protobuf:"bytes,2,opt,name=hash_costs,json=hashCosts,proto3" json:"hash_costs,omitempty"`
	Options                   *EncryptionOptions `protobuf:"bytes,4,opt,name=options,proto3" json:"options,omitempty"`
	UseFsKeyringForV1Policies bool               `protobuf:"varint,5,opt,name=use_fs_keyring_for_v1_policies,json=useFsKeyringForV1Policies,proto3" json:"use_fs_keyring_for_v1_policies,omitempty"`
	XXX_NoUnkeyedLiteral      struct{}           `json:"-"`
	XXX_unrecognized          []byte             `json:"-"`
	XXX_sizecache             int32              `json:"-"`
}

func (m *Config) Reset()         { *m = Config{} }
func (m *Config) String() string { return proto.CompactTextString(m) }
func (*Config) ProtoMessage()    {}
func (*Config) Descriptor() ([]byte, []int) {
	return fileDescriptor_metadata_20fa0d9b7a38c428, []int{6}
}
func (m *Config) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Config.Unmarshal(m, b)
}
func (m *Config) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Config.Marshal(b, m, deterministic)
}
func (dst *Config) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Config.Merge(dst, src)
}
func (m *Config) XXX_Size() int {
	return xxx_messageInfo_Config.Size(m)
}
func (m *Config) XXX_DiscardUnknown() {
	xxx_messageInfo_Config.DiscardUnknown(m)
}

var xxx_messageInfo_Config proto.InternalMessageInfo

func (m *Config) GetSource() SourceType {
	if m != nil {
		return m.Source
	}
	return SourceType_default
}

func (m *Config) GetHashCosts() *HashingCosts {
	if m != nil {
		return m.HashCosts
	}
	return nil
}

func (m *Config) GetOptions() *EncryptionOptions {
	if m != nil {
		return m.Options
	}
	return nil
}

func (m *Config) GetUseFsKeyringForV1Policies() bool {
	if m != nil {
		return m.UseFsKeyringForV1Policies
	}
	return false
}

func init() {
	proto.RegisterType((*HashingCosts)(nil), "metadata.HashingCosts")
	proto.RegisterType((*WrappedKeyData)(nil), "metadata.WrappedKeyData")
	proto.RegisterType((*ProtectorData)(nil), "metadata.ProtectorData")
	proto.RegisterType((*EncryptionOptions)(nil), "metadata.EncryptionOptions")
	proto.RegisterType((*WrappedPolicyKey)(nil), "metadata.WrappedPolicyKey")
	proto.RegisterType((*PolicyData)(nil), "metadata.PolicyData")
	proto.RegisterType((*Config)(nil), "metadata.Config")
	proto.RegisterEnum("metadata.SourceType", SourceType_name, SourceType_value)
	proto.RegisterEnum("metadata.EncryptionOptions_Mode", EncryptionOptions_Mode_name, EncryptionOptions_Mode_value)
}

func init() { proto.RegisterFile("metadata/metadata.proto", fileDescriptor_metadata_20fa0d9b7a38c428) }

var fileDescriptor_metadata_20fa0d9b7a38c428 = []byte{
	// 716 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x9c, 0x54, 0xdd, 0x6a, 0xdb, 0x48,
	0x14, 0x5e, 0x49, 0x8e, 0x7f, 0x8e, 0x7f, 0x56, 0x99, 0x64, 0xb3, 0xda, 0x5d, 0x58, 0x8c, 0x97,
	0x40, 0x58, 0x42, 0x16, 0x7b, 0x49, 0x69, 0xa1, 0x14, 0x52, 0x27, 0x69, 0x93, 0x10, 0x9a, 0x8e,
	0x8d, 0xdb, 0x42, 0x41, 0x4c, 0xa4, 0xb1, 0x3d, 0x58, 0xd2, 0x88, 0x99, 0x71, 0x8c, 0xee, 0x7a,
	0xd7, 0x07, 0xe8, 0xbb, 0xf4, 0x69, 0xfa, 0x28, 0xbd, 0x28, 0x1a, 0xc9, 0x7f, 0x09, 0x84, 0xa4,
	0x37, 0xe2, 0x9c, 0x6f, 0xce, 0xef, 0x77, 0xce, 0x11, 0xfc, 0x1e, 0x52, 0x45, 0x7c, 0xa2, 0xc8,
	0x7f, 0x73, 0xe1, 0x20, 0x16, 0x5c, 0x71, 0x54, 0x9e, 0xeb, 0xad, 0x8f, 0x50, 0x7b, 0x4d, 0xe4,
	0x98, 0x45, 0xa3, 0x2e, 0x97, 0x4a, 0x22, 0x04, 0x05, 0xc5, 0x42, 0xea, 0x98, 0x4d, 0x63, 0xcf,
	0xc2, 0x5a, 0x46, 0x3b, 0x50, 0x0c, 0x69, 0xc8, 0x45, 0xe2, 0x58, 0x1a, 0xcd, 0x35, 0xd4, 0x84,
	0x6a, 0x4c, 0x04, 0x09, 0x02, 0x1a, 0x30, 0x19, 0x3a, 0x05, 0xfd, 0xb8, 0x0a, 0xb5, 0x3e, 0x40,
	0xe3, 0x9d, 0x20, 0x71, 0x4c, 0xfd, 0x0b, 0x9a, 0x1c, 0x13, 0x45, 0x50, 0x03, 0xcc, 0xb3, 0x81,
	0x63, 0x34, 0x8d, 0xbd, 0x1a, 0x36, 0xcf, 0x06, 0xe8, 0x1f, 0xa8, 0xd3, 0xc8, 0x13, 0x49, 0xac,
	0xa8, 0xef, 0x4e, 0x68, 0xa2, 0x13, 0xd7, 0x70, 0x6d, 0x01, 0x5e, 0xd0, 0x24, 0x2d, 0x6a, 0x1c,
	0x12, 0x4f, 0xa7, 0xaf, 0x61, 0x2d, 0xb7, 0xbe, 0x98, 0x50, 0xbf, 0x12, 0x5c, 0x51, 0x4f, 0x71,
	0xa1, 0x43, 0xb7, 0x61, 0x3b, 0x9e, 0x03, 0xae, 0x4f, 0xa5, 0x27, 0x58, 0xac, 0xb8, 0xd0, 0xc9,
	0x2a, 0x78, 0x6b, 0xf1, 0x76, 0xbc, 0x78, 0x42, 0xfb, 0x50, 0x94, 0x7c, 0x2a, 0xbc, 0xac, 0xdf,
	0x46, 0x67, 0xfb, 0x60, 0x41, 0x54, 0x4f, 0xe3, 0xfd, 0x24, 0xa6, 0x38, 0xb7, 0x49, 0xcb, 0x88,
	0x48, 0x48, 0x75, 0x19, 0x15, 0xac, 0x65, 0xb4, 0x0f, 0x1b, 0x5e, 0x4a, 0x9c, 0xee, 0xbe, 0xda,
	0xd9, 0x59, 0x06, 0x58, 0xa5, 0x15, 0x67, 0x46, 0x69, 0x04, 0x49, 0x02, 0xe5, 0x6c, 0x64, 0x8d,
	0xa4, 0x32, 0xb2, 0xc1, 0x9a, 0x32, 0xdf, 0x29, 0x6a, 0xf6, 0x52, 0x11, 0x3d, 0x83, 0xea, 0x2c,
	0x63, 0x4d, 0x33, 0x52, 0xd2, 0x91, 0x9d, 0x65, 0xe4, 0x75, 0x4a, 0x31, 0xcc, 0x16, 0x7a, 0xeb,
	0x9b, 0x09, 0x9b, 0x27, 0x19, 0x75, 0x8c, 0x47, 0x6f, 0xf4, 0x57, 0x22, 0x07, 0x4a, 0x31, 0xf1,
	0x7d, 0x16, 0x8d, 0x34, 0x19, 0x16, 0x9e, 0xab, 0xe8, 0x39, 0x94, 0x3d, 0x1e, 0x29, 0x1a, 0x29,
	0x99, 0x53, 0xd0, 0x5c, 0xe6, 0xb9, 0x13, 0xe8, 0xe0, 0x92, 0xfb, 0x14, 0x2f, 0x3c, 0xd0, 0x0b,
	0xa8, 0x0c, 0x59, 0x40, 0x53, 0x22, 0xa4, 0x66, 0xe5, 0x21, 0xee, 0x4b, 0x17, 0xb4, 0x0b, 0x8d,
	0x98, 0x07, 0xcc, 0x4b, 0xdc, 0x1b, 0x2a, 0x24, 0xe3, 0x51, 0xbe, 0x43, 0xf5, 0x0c, 0x1d, 0x64,
	0x60, 0xeb, 0xb3, 0x01, 0x85, 0xd4, 0x15, 0x55, 0xa1, 0xe4, 0xd3, 0x21, 0x99, 0x06, 0xca, 0xfe,
	0x05, 0xfd, 0x0a, 0xd5, 0xa3, 0x93, 0x9e, 0xdb, 0x39, 0x7c, 0xe2, 0xbe, 0xef, 0xf7, 0x6c, 0x63,
	0x15, 0x78, 0xd5, 0xbd, 0xb4, 0xcd, 0x55, 0xa0, 0xfb, 0xb2, 0x6b, 0x5b, 0x6b, 0x40, 0xbf, 0x67,
	0x17, 0xe6, 0x40, 0xbb, 0xf3, 0x54, 0x5b, 0x6c, 0xac, 0x01, 0xfd, 0x9e, 0x5d, 0x44, 0x35, 0x28,
	0x1f, 0xf9, 0x8c, 0x44, 0x6a, 0x1a, 0xda, 0x95, 0xd6, 0x27, 0x03, 0xec, 0x9c, 0xfd, 0x2b, 0x5d,
	0x62, 0xba, 0x9d, 0x3f, 0xb1, 0x77, 0xb7, 0x26, 0x6c, 0x3e, 0x62, 0xc2, 0x5f, 0x0d, 0x80, 0x2c,
	0xb7, 0x5e, 0xfa, 0x5d, 0x68, 0x4c, 0x68, 0x72, 0x37, 0x6d, 0x7d, 0x42, 0x93, 0x95, 0x84, 0x87,
	0x50, 0xe2, 0xd9, 0x10, 0xf2, 0x64, 0x7f, 0xdd, 0x33, 0x27, 0x3c, 0xb7, 0x45, 0xe7, 0xb0, 0x35,
	0xaf, 0x33, 0x1f, 0xd4, 0x84, 0x26, 0xe9, 0xa8, 0xad, 0xbd, 0x6a, 0xe7, 0xcf, 0x3b, 0xf5, 0x2e,
	0x38, 0xc1, 0x9b, 0xb3, 0x5b, 0x88, 0x6c, 0x7d, 0x37, 0xa0, 0xd8, 0xe5, 0xd1, 0x90, 0x8d, 0x56,
	0xce, 0xce, 0x78, 0xc0, 0xd9, 0x1d, 0x02, 0x8c, 0x89, 0x1c, 0xbb, 0xd9, 0x9d, 0x99, 0xf7, 0xde,
	0x59, 0x25, 0xb5, 0xcc, 0xfe, 0x64, 0x2b, 0x2d, 0x17, 0x1e, 0xd1, 0xf2, 0x11, 0xfc, 0x3d, 0x95,
	0xd4, 0x1d, 0xca, 0xb4, 0x55, 0xc1, 0xa2, 0x91, 0x3b, 0xe4, 0xc2, 0xbd, 0x69, 0x67, 0x04, 0x30,
	0x2a, 0xf5, 0xf1, 0x96, 0xf1, 0x1f, 0x53, 0x49, 0x4f, 0xe5, 0x45, 0x66, 0x73, 0xca, 0xc5, 0xa0,
	0x7d, 0x95, 0x1b, 0x9c, 0x17, 0xca, 0x96, 0x5d, 0xc0, 0x75, 0x8f, 0x87, 0x31, 0x51, 0xec, 0x9a,
	0x05, 0x4c, 0x25, 0xff, 0xbe, 0x05, 0x58, 0xf6, 0xb6, 0xbe, 0xc9, 0x08, 0x1a, 0x31, 0x09, 0xdd,
	0x98, 0x48, 0x19, 0x8f, 0x05, 0x91, 0xd4, 0x36, 0xd0, 0x6f, 0xb0, 0xe9, 0x4d, 0xa5, 0xe2, 0x6b,
	0xb0, 0x99, 0xfa, 0x09, 0x32, 0x4b, 0x4b, 0xb3, 0xad, 0xeb, 0xa2, 0xfe, 0x99, 0xff, 0xff, 0x23,
	0x00, 0x00, 0xff, 0xff, 0x3d, 0x33, 0x9f, 0x0d, 0xe7, 0x05, 0x00, 0x00,
}
  "AES_256_GCM": 2,
  "AES_256_CBC": 3,
  "AES_256_CTS": 4,
  "AES_128_CBC": 5,
  "AES_128_CTS": 6,
  "Adiantum":    9,
}

func (x EncryptionOptions_Mode) String() string {
  return proto.EnumName(EncryptionOptions_Mode_name, int32(x))
}

func (EncryptionOptions_Mode) EnumDescriptor() ([]byte, []int) {
  return fileDescriptor_metadata_20fa0d9b7a38c428, []int{3, 0}
}

type HashingCosts struct {
  Time int64 `protobuf:"varint,2,opt,name=time,proto3" json:"time,omitempty"`
  Memory int64 `protobuf:"varint,3,opt,name=memory,proto3" json:"memory,omitempty"`
  Parallelism int64 `protobuf:"varint,4,opt,name=parallelism,proto3" json: parallelism, omitempty`
  xxx_NoUnkeyedLiteral struct{} `json:"-"`
  xxx_unrecognized []byte `json:"-"`
  xxx_sizecache int32 `json:"-"`
}

func (m *ProtectorData) reset() {*m = ProtectorData{}}
func (m *ProtectorData) String() string {return proto.CompactTextString9m}
func (*ProtectorData) ProtoMessage() {}
func (*ProtectorData) Descriptor() ([]byte, []int) {
  return fileDescriptor_metadata_20fa0d9b7a38c428, []int{2}
}

func (m *ProtectorData) xxx_Unmarshal(b []byte) error {
  return xxx_messageInfo_ProtectorData.Unmarshal(m, b)
}

func (m *ProtectorData) xxx_Marshal(b []byte, deterministic bool) ([]byte error) {
  return xxx_messageInfo_ProtectorData.Marshal(b, m, deterministic)
}

func (dst *ProtectorData) xxx_Merge(src, proto.message) {
  xxx_messageInfo_ProtectorData.Merge(dst, src)
}

func (m *ProtectorData) xxx_Size() int {
  return xxx_messageInfo_ProtectorData.Size(m)
}

var xxx_messageInfo_ProtectorData proto.InternalMessageInfo

func (m *HashingCosts) GetTime() int64 {
  if m != nil {
    return m.Time
  }
  return 0
}

func (m *HashingCosts) GetMemmory() int64 {
  if m != nil {
    return m.Memory
  }
  return 0
}

func (m *HashingCosts) GetParallelism() int64 {
  if m != nil {
    return m.Parallelism
  }
  return 0
}

func (m *HashingCosts) GetParallelism() int64 {
  if m != nil {
    return m.Parallelism
  }
  return 0
}

type WrappedKeyData struct {
  IV []byte `protobuf:"bytes,1,opt,name=IV,proto3", json="IV,omitempty"`
  EncryptedKey []byte `protobuf:"bytes,2,opt,name=encrypted_key,json=encryptedKey,proto3", json:"encrypted_key, omitempty"`
}

