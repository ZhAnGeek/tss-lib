// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.0
// 	protoc        v3.19.4
// source: protob/kcdsa-signing.proto

package signing

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// Represents a BROADCAST message sent during Round 1 of the KCDSA TSS keygen protocol.
type SignRound1Message struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	KCommitment []byte `protobuf:"bytes,1,opt,name=k_commitment,json=kCommitment,proto3" json:"k_commitment,omitempty"` // used as vss share
}

func (x *SignRound1Message) Reset() {
	*x = SignRound1Message{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_kcdsa_signing_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignRound1Message) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignRound1Message) ProtoMessage() {}

func (x *SignRound1Message) ProtoReflect() protoreflect.Message {
	mi := &file_protob_kcdsa_signing_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignRound1Message.ProtoReflect.Descriptor instead.
func (*SignRound1Message) Descriptor() ([]byte, []int) {
	return file_protob_kcdsa_signing_proto_rawDescGZIP(), []int{0}
}

func (x *SignRound1Message) GetKCommitment() []byte {
	if x != nil {
		return x.KCommitment
	}
	return nil
}

// Represents a BROADCAST message sent during Round 1 of the KCDSA TSS keygen protocol.
type SignRound2Message1 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	KDeCommitment [][]byte `protobuf:"bytes,1,rep,name=k_de_commitment,json=kDeCommitment,proto3" json:"k_de_commitment,omitempty"`
	ProofK        [][]byte `protobuf:"bytes,2,rep,name=proofK,proto3" json:"proofK,omitempty"`
}

func (x *SignRound2Message1) Reset() {
	*x = SignRound2Message1{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_kcdsa_signing_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignRound2Message1) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignRound2Message1) ProtoMessage() {}

func (x *SignRound2Message1) ProtoReflect() protoreflect.Message {
	mi := &file_protob_kcdsa_signing_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignRound2Message1.ProtoReflect.Descriptor instead.
func (*SignRound2Message1) Descriptor() ([]byte, []int) {
	return file_protob_kcdsa_signing_proto_rawDescGZIP(), []int{1}
}

func (x *SignRound2Message1) GetKDeCommitment() [][]byte {
	if x != nil {
		return x.KDeCommitment
	}
	return nil
}

func (x *SignRound2Message1) GetProofK() [][]byte {
	if x != nil {
		return x.ProofK
	}
	return nil
}

// Represents a BROADCAST message sent during Round 1 of the KCDSA TSS keygen protocol.
type SignRound3Message1 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	K []byte `protobuf:"bytes,1,opt,name=K,proto3" json:"K,omitempty"` // used as mta, represent k substract e
	X []byte `protobuf:"bytes,2,opt,name=X,proto3" json:"X,omitempty"` // used as mta, x
}

func (x *SignRound3Message1) Reset() {
	*x = SignRound3Message1{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_kcdsa_signing_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignRound3Message1) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignRound3Message1) ProtoMessage() {}

func (x *SignRound3Message1) ProtoReflect() protoreflect.Message {
	mi := &file_protob_kcdsa_signing_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignRound3Message1.ProtoReflect.Descriptor instead.
func (*SignRound3Message1) Descriptor() ([]byte, []int) {
	return file_protob_kcdsa_signing_proto_rawDescGZIP(), []int{2}
}

func (x *SignRound3Message1) GetK() []byte {
	if x != nil {
		return x.K
	}
	return nil
}

func (x *SignRound3Message1) GetX() []byte {
	if x != nil {
		return x.X
	}
	return nil
}

// Represents a P2P message sent during Round 1 of the KCDSA TSS keygen protocol.
type SignRound3Message2 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	EncProof [][]byte `protobuf:"bytes,3,rep,name=EncProof,proto3" json:"EncProof,omitempty"` // used as mta, represent k substract e
}

func (x *SignRound3Message2) Reset() {
	*x = SignRound3Message2{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_kcdsa_signing_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignRound3Message2) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignRound3Message2) ProtoMessage() {}

func (x *SignRound3Message2) ProtoReflect() protoreflect.Message {
	mi := &file_protob_kcdsa_signing_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignRound3Message2.ProtoReflect.Descriptor instead.
func (*SignRound3Message2) Descriptor() ([]byte, []int) {
	return file_protob_kcdsa_signing_proto_rawDescGZIP(), []int{3}
}

func (x *SignRound3Message2) GetEncProof() [][]byte {
	if x != nil {
		return x.EncProof
	}
	return nil
}

// Represents a P2P message sent to each party during Round 2 of the ECDSA TSS signing protocol.
type SignRound4Message1 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	BigXShare    [][]byte `protobuf:"bytes,1,rep,name=BigXShare,proto3" json:"BigXShare,omitempty"`
	DjiKX        []byte   `protobuf:"bytes,2,opt,name=DjiKX,proto3" json:"DjiKX,omitempty"`
	FjiKX        []byte   `protobuf:"bytes,3,opt,name=FjiKX,proto3" json:"FjiKX,omitempty"`
	AffgProofKX  [][]byte `protobuf:"bytes,4,rep,name=AffgProofKX,proto3" json:"AffgProofKX,omitempty"`
	LogstarProof [][]byte `protobuf:"bytes,5,rep,name=LogstarProof,proto3" json:"LogstarProof,omitempty"`
}

func (x *SignRound4Message1) Reset() {
	*x = SignRound4Message1{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_kcdsa_signing_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignRound4Message1) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignRound4Message1) ProtoMessage() {}

func (x *SignRound4Message1) ProtoReflect() protoreflect.Message {
	mi := &file_protob_kcdsa_signing_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignRound4Message1.ProtoReflect.Descriptor instead.
func (*SignRound4Message1) Descriptor() ([]byte, []int) {
	return file_protob_kcdsa_signing_proto_rawDescGZIP(), []int{4}
}

func (x *SignRound4Message1) GetBigXShare() [][]byte {
	if x != nil {
		return x.BigXShare
	}
	return nil
}

func (x *SignRound4Message1) GetDjiKX() []byte {
	if x != nil {
		return x.DjiKX
	}
	return nil
}

func (x *SignRound4Message1) GetFjiKX() []byte {
	if x != nil {
		return x.FjiKX
	}
	return nil
}

func (x *SignRound4Message1) GetAffgProofKX() [][]byte {
	if x != nil {
		return x.AffgProofKX
	}
	return nil
}

func (x *SignRound4Message1) GetLogstarProof() [][]byte {
	if x != nil {
		return x.LogstarProof
	}
	return nil
}

// Represents a P2P message sent to all parties during Round 3 of the ECDSA TSS signing protocol.
type SignRound5Message1 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	KXShare      []byte   `protobuf:"bytes,1,opt,name=KXShare,proto3" json:"KXShare,omitempty"`
	BigKXShare   [][]byte `protobuf:"bytes,2,rep,name=BigKXShare,proto3" json:"BigKXShare,omitempty"`
	ProofLogstar [][]byte `protobuf:"bytes,3,rep,name=ProofLogstar,proto3" json:"ProofLogstar,omitempty"`
}

func (x *SignRound5Message1) Reset() {
	*x = SignRound5Message1{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_kcdsa_signing_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignRound5Message1) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignRound5Message1) ProtoMessage() {}

func (x *SignRound5Message1) ProtoReflect() protoreflect.Message {
	mi := &file_protob_kcdsa_signing_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignRound5Message1.ProtoReflect.Descriptor instead.
func (*SignRound5Message1) Descriptor() ([]byte, []int) {
	return file_protob_kcdsa_signing_proto_rawDescGZIP(), []int{5}
}

func (x *SignRound5Message1) GetKXShare() []byte {
	if x != nil {
		return x.KXShare
	}
	return nil
}

func (x *SignRound5Message1) GetBigKXShare() [][]byte {
	if x != nil {
		return x.BigKXShare
	}
	return nil
}

func (x *SignRound5Message1) GetProofLogstar() [][]byte {
	if x != nil {
		return x.ProofLogstar
	}
	return nil
}

var File_protob_kcdsa_signing_proto protoreflect.FileDescriptor

var file_protob_kcdsa_signing_proto_rawDesc = []byte{
	0x0a, 0x1a, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x2f, 0x6b, 0x63, 0x64, 0x73, 0x61, 0x2d, 0x73,
	0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x1c, 0x62, 0x69,
	0x6e, 0x61, 0x6e, 0x63, 0x65, 0x2e, 0x74, 0x73, 0x73, 0x6c, 0x69, 0x62, 0x2e, 0x6b, 0x63, 0x64,
	0x73, 0x61, 0x2e, 0x73, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x22, 0x36, 0x0a, 0x11, 0x53, 0x69,
	0x67, 0x6e, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x31, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12,
	0x21, 0x0a, 0x0c, 0x6b, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0b, 0x6b, 0x43, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65,
	0x6e, 0x74, 0x22, 0x54, 0x0a, 0x12, 0x53, 0x69, 0x67, 0x6e, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x32,
	0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x31, 0x12, 0x26, 0x0a, 0x0f, 0x6b, 0x5f, 0x64, 0x65,
	0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x18, 0x01, 0x20, 0x03, 0x28,
	0x0c, 0x52, 0x0d, 0x6b, 0x44, 0x65, 0x43, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74,
	0x12, 0x16, 0x0a, 0x06, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x4b, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0c,
	0x52, 0x06, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x4b, 0x22, 0x30, 0x0a, 0x12, 0x53, 0x69, 0x67, 0x6e,
	0x52, 0x6f, 0x75, 0x6e, 0x64, 0x33, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x31, 0x12, 0x0c,
	0x0a, 0x01, 0x4b, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x01, 0x4b, 0x12, 0x0c, 0x0a, 0x01,
	0x58, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x01, 0x58, 0x22, 0x30, 0x0a, 0x12, 0x53, 0x69,
	0x67, 0x6e, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x33, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x32,
	0x12, 0x1a, 0x0a, 0x08, 0x45, 0x6e, 0x63, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x18, 0x03, 0x20, 0x03,
	0x28, 0x0c, 0x52, 0x08, 0x45, 0x6e, 0x63, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x22, 0xa4, 0x01, 0x0a,
	0x12, 0x53, 0x69, 0x67, 0x6e, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x34, 0x4d, 0x65, 0x73, 0x73, 0x61,
	0x67, 0x65, 0x31, 0x12, 0x1c, 0x0a, 0x09, 0x42, 0x69, 0x67, 0x58, 0x53, 0x68, 0x61, 0x72, 0x65,
	0x18, 0x01, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x09, 0x42, 0x69, 0x67, 0x58, 0x53, 0x68, 0x61, 0x72,
	0x65, 0x12, 0x14, 0x0a, 0x05, 0x44, 0x6a, 0x69, 0x4b, 0x58, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c,
	0x52, 0x05, 0x44, 0x6a, 0x69, 0x4b, 0x58, 0x12, 0x14, 0x0a, 0x05, 0x46, 0x6a, 0x69, 0x4b, 0x58,
	0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x05, 0x46, 0x6a, 0x69, 0x4b, 0x58, 0x12, 0x20, 0x0a,
	0x0b, 0x41, 0x66, 0x66, 0x67, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x4b, 0x58, 0x18, 0x04, 0x20, 0x03,
	0x28, 0x0c, 0x52, 0x0b, 0x41, 0x66, 0x66, 0x67, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x4b, 0x58, 0x12,
	0x22, 0x0a, 0x0c, 0x4c, 0x6f, 0x67, 0x73, 0x74, 0x61, 0x72, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x18,
	0x05, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x0c, 0x4c, 0x6f, 0x67, 0x73, 0x74, 0x61, 0x72, 0x50, 0x72,
	0x6f, 0x6f, 0x66, 0x22, 0x72, 0x0a, 0x12, 0x53, 0x69, 0x67, 0x6e, 0x52, 0x6f, 0x75, 0x6e, 0x64,
	0x35, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x31, 0x12, 0x18, 0x0a, 0x07, 0x4b, 0x58, 0x53,
	0x68, 0x61, 0x72, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x07, 0x4b, 0x58, 0x53, 0x68,
	0x61, 0x72, 0x65, 0x12, 0x1e, 0x0a, 0x0a, 0x42, 0x69, 0x67, 0x4b, 0x58, 0x53, 0x68, 0x61, 0x72,
	0x65, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x0a, 0x42, 0x69, 0x67, 0x4b, 0x58, 0x53, 0x68,
	0x61, 0x72, 0x65, 0x12, 0x22, 0x0a, 0x0c, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x4c, 0x6f, 0x67, 0x73,
	0x74, 0x61, 0x72, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x0c, 0x50, 0x72, 0x6f, 0x6f, 0x66,
	0x4c, 0x6f, 0x67, 0x73, 0x74, 0x61, 0x72, 0x42, 0x0f, 0x5a, 0x0d, 0x6b, 0x63, 0x64, 0x73, 0x61,
	0x2f, 0x73, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_protob_kcdsa_signing_proto_rawDescOnce sync.Once
	file_protob_kcdsa_signing_proto_rawDescData = file_protob_kcdsa_signing_proto_rawDesc
)

func file_protob_kcdsa_signing_proto_rawDescGZIP() []byte {
	file_protob_kcdsa_signing_proto_rawDescOnce.Do(func() {
		file_protob_kcdsa_signing_proto_rawDescData = protoimpl.X.CompressGZIP(file_protob_kcdsa_signing_proto_rawDescData)
	})
	return file_protob_kcdsa_signing_proto_rawDescData
}

var file_protob_kcdsa_signing_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_protob_kcdsa_signing_proto_goTypes = []interface{}{
	(*SignRound1Message)(nil),  // 0: binance.tsslib.kcdsa.signing.SignRound1Message
	(*SignRound2Message1)(nil), // 1: binance.tsslib.kcdsa.signing.SignRound2Message1
	(*SignRound3Message1)(nil), // 2: binance.tsslib.kcdsa.signing.SignRound3Message1
	(*SignRound3Message2)(nil), // 3: binance.tsslib.kcdsa.signing.SignRound3Message2
	(*SignRound4Message1)(nil), // 4: binance.tsslib.kcdsa.signing.SignRound4Message1
	(*SignRound5Message1)(nil), // 5: binance.tsslib.kcdsa.signing.SignRound5Message1
}
var file_protob_kcdsa_signing_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_protob_kcdsa_signing_proto_init() }
func file_protob_kcdsa_signing_proto_init() {
	if File_protob_kcdsa_signing_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_protob_kcdsa_signing_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignRound1Message); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_protob_kcdsa_signing_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignRound2Message1); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_protob_kcdsa_signing_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignRound3Message1); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_protob_kcdsa_signing_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignRound3Message2); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_protob_kcdsa_signing_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignRound4Message1); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_protob_kcdsa_signing_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignRound5Message1); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_protob_kcdsa_signing_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_protob_kcdsa_signing_proto_goTypes,
		DependencyIndexes: file_protob_kcdsa_signing_proto_depIdxs,
		MessageInfos:      file_protob_kcdsa_signing_proto_msgTypes,
	}.Build()
	File_protob_kcdsa_signing_proto = out.File
	file_protob_kcdsa_signing_proto_rawDesc = nil
	file_protob_kcdsa_signing_proto_goTypes = nil
	file_protob_kcdsa_signing_proto_depIdxs = nil
}
