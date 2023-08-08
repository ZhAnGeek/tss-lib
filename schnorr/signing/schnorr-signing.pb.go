// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.0
// 	protoc        v3.21.2
// source: protob/schnorr-signing.proto

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

// Represents a BROADCAST message sent to all parties during Round 1 of the Schnorr TSS signing protocol.
type SignRound1Message struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Commitment []byte `protobuf:"bytes,1,opt,name=commitment,proto3" json:"commitment,omitempty"`
}

func (x *SignRound1Message) Reset() {
	*x = SignRound1Message{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_schnorr_signing_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignRound1Message) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignRound1Message) ProtoMessage() {}

func (x *SignRound1Message) ProtoReflect() protoreflect.Message {
	mi := &file_protob_schnorr_signing_proto_msgTypes[0]
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
	return file_protob_schnorr_signing_proto_rawDescGZIP(), []int{0}
}

func (x *SignRound1Message) GetCommitment() []byte {
	if x != nil {
		return x.Commitment
	}
	return nil
}

// Represents a BROADCAST message sent to all parties during Round 2 of the Schnorr TSS signing protocol.
type SignRound2Message struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	DeCommitment [][]byte `protobuf:"bytes,1,rep,name=de_commitment,json=deCommitment,proto3" json:"de_commitment,omitempty"`
	ProofD       [][]byte `protobuf:"bytes,2,rep,name=proofD,proto3" json:"proofD,omitempty"`
	ProofE       [][]byte `protobuf:"bytes,3,rep,name=proofE,proto3" json:"proofE,omitempty"`
}

func (x *SignRound2Message) Reset() {
	*x = SignRound2Message{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_schnorr_signing_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignRound2Message) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignRound2Message) ProtoMessage() {}

func (x *SignRound2Message) ProtoReflect() protoreflect.Message {
	mi := &file_protob_schnorr_signing_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignRound2Message.ProtoReflect.Descriptor instead.
func (*SignRound2Message) Descriptor() ([]byte, []int) {
	return file_protob_schnorr_signing_proto_rawDescGZIP(), []int{1}
}

func (x *SignRound2Message) GetDeCommitment() [][]byte {
	if x != nil {
		return x.DeCommitment
	}
	return nil
}

func (x *SignRound2Message) GetProofD() [][]byte {
	if x != nil {
		return x.ProofD
	}
	return nil
}

func (x *SignRound2Message) GetProofE() [][]byte {
	if x != nil {
		return x.ProofE
	}
	return nil
}

// Represents a BROADCAST message sent to all parties during Round 3 of the Schnorr TSS signing protocol.
type SignRound3Message struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Zi []byte `protobuf:"bytes,1,opt,name=zi,proto3" json:"zi,omitempty"`
}

func (x *SignRound3Message) Reset() {
	*x = SignRound3Message{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_schnorr_signing_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignRound3Message) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignRound3Message) ProtoMessage() {}

func (x *SignRound3Message) ProtoReflect() protoreflect.Message {
	mi := &file_protob_schnorr_signing_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignRound3Message.ProtoReflect.Descriptor instead.
func (*SignRound3Message) Descriptor() ([]byte, []int) {
	return file_protob_schnorr_signing_proto_rawDescGZIP(), []int{2}
}

func (x *SignRound3Message) GetZi() []byte {
	if x != nil {
		return x.Zi
	}
	return nil
}

var File_protob_schnorr_signing_proto protoreflect.FileDescriptor

var file_protob_schnorr_signing_proto_rawDesc = []byte{
	0x0a, 0x1c, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x2f, 0x73, 0x63, 0x68, 0x6e, 0x6f, 0x72, 0x72,
	0x2d, 0x73, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x1e,
	0x62, 0x69, 0x6e, 0x61, 0x6e, 0x63, 0x65, 0x2e, 0x74, 0x73, 0x73, 0x6c, 0x69, 0x62, 0x2e, 0x73,
	0x63, 0x68, 0x6e, 0x6f, 0x72, 0x72, 0x2e, 0x73, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x22, 0x33,
	0x0a, 0x11, 0x53, 0x69, 0x67, 0x6e, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x31, 0x4d, 0x65, 0x73, 0x73,
	0x61, 0x67, 0x65, 0x12, 0x1e, 0x0a, 0x0a, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e,
	0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0a, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d,
	0x65, 0x6e, 0x74, 0x22, 0x68, 0x0a, 0x11, 0x53, 0x69, 0x67, 0x6e, 0x52, 0x6f, 0x75, 0x6e, 0x64,
	0x32, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x23, 0x0a, 0x0d, 0x64, 0x65, 0x5f, 0x63,
	0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0c, 0x52,
	0x0c, 0x64, 0x65, 0x43, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x12, 0x16, 0x0a,
	0x06, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x44, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x06, 0x70,
	0x72, 0x6f, 0x6f, 0x66, 0x44, 0x12, 0x16, 0x0a, 0x06, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x45, 0x18,
	0x03, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x06, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x45, 0x22, 0x23, 0x0a,
	0x11, 0x53, 0x69, 0x67, 0x6e, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x33, 0x4d, 0x65, 0x73, 0x73, 0x61,
	0x67, 0x65, 0x12, 0x0e, 0x0a, 0x02, 0x7a, 0x69, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x02,
	0x7a, 0x69, 0x42, 0x11, 0x5a, 0x0f, 0x73, 0x63, 0x68, 0x6e, 0x6f, 0x72, 0x72, 0x2f, 0x73, 0x69,
	0x67, 0x6e, 0x69, 0x6e, 0x67, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_protob_schnorr_signing_proto_rawDescOnce sync.Once
	file_protob_schnorr_signing_proto_rawDescData = file_protob_schnorr_signing_proto_rawDesc
)

func file_protob_schnorr_signing_proto_rawDescGZIP() []byte {
	file_protob_schnorr_signing_proto_rawDescOnce.Do(func() {
		file_protob_schnorr_signing_proto_rawDescData = protoimpl.X.CompressGZIP(file_protob_schnorr_signing_proto_rawDescData)
	})
	return file_protob_schnorr_signing_proto_rawDescData
}

var file_protob_schnorr_signing_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_protob_schnorr_signing_proto_goTypes = []interface{}{
	(*SignRound1Message)(nil), // 0: binance.tsslib.schnorr.signing.SignRound1Message
	(*SignRound2Message)(nil), // 1: binance.tsslib.schnorr.signing.SignRound2Message
	(*SignRound3Message)(nil), // 2: binance.tsslib.schnorr.signing.SignRound3Message
}
var file_protob_schnorr_signing_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_protob_schnorr_signing_proto_init() }
func file_protob_schnorr_signing_proto_init() {
	if File_protob_schnorr_signing_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_protob_schnorr_signing_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
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
		file_protob_schnorr_signing_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignRound2Message); i {
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
		file_protob_schnorr_signing_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignRound3Message); i {
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
			RawDescriptor: file_protob_schnorr_signing_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_protob_schnorr_signing_proto_goTypes,
		DependencyIndexes: file_protob_schnorr_signing_proto_depIdxs,
		MessageInfos:      file_protob_schnorr_signing_proto_msgTypes,
	}.Build()
	File_protob_schnorr_signing_proto = out.File
	file_protob_schnorr_signing_proto_rawDesc = nil
	file_protob_schnorr_signing_proto_goTypes = nil
	file_protob_schnorr_signing_proto_depIdxs = nil
}
