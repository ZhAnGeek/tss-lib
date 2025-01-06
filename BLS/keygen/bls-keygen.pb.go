// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.31.0
// 	protoc        v4.25.3
// source: binance/tsslib/v2/protob/bls-keygen.proto

package keygen

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

// Represents a BROADCAST message sent during Round 1 of the BLS TSS keygen protocol.
type KGRound1Message struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Commitment []byte `protobuf:"bytes,1,opt,name=commitment,proto3" json:"commitment,omitempty"`
}

func (x *KGRound1Message) Reset() {
	*x = KGRound1Message{}
	if protoimpl.UnsafeEnabled {
		mi := &file_binance_tsslib_v2_protob_bls_keygen_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *KGRound1Message) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*KGRound1Message) ProtoMessage() {}

func (x *KGRound1Message) ProtoReflect() protoreflect.Message {
	mi := &file_binance_tsslib_v2_protob_bls_keygen_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use KGRound1Message.ProtoReflect.Descriptor instead.
func (*KGRound1Message) Descriptor() ([]byte, []int) {
	return file_binance_tsslib_v2_protob_bls_keygen_proto_rawDescGZIP(), []int{0}
}

func (x *KGRound1Message) GetCommitment() []byte {
	if x != nil {
		return x.Commitment
	}
	return nil
}

// Represents a P2P message sent to each party during Round 2 of the BLS TSS keygen protocol.
type KGRound2Message1 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Share []byte `protobuf:"bytes,1,opt,name=share,proto3" json:"share,omitempty"`
}

func (x *KGRound2Message1) Reset() {
	*x = KGRound2Message1{}
	if protoimpl.UnsafeEnabled {
		mi := &file_binance_tsslib_v2_protob_bls_keygen_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *KGRound2Message1) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*KGRound2Message1) ProtoMessage() {}

func (x *KGRound2Message1) ProtoReflect() protoreflect.Message {
	mi := &file_binance_tsslib_v2_protob_bls_keygen_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use KGRound2Message1.ProtoReflect.Descriptor instead.
func (*KGRound2Message1) Descriptor() ([]byte, []int) {
	return file_binance_tsslib_v2_protob_bls_keygen_proto_rawDescGZIP(), []int{1}
}

func (x *KGRound2Message1) GetShare() []byte {
	if x != nil {
		return x.Share
	}
	return nil
}

// Represents a BROADCAST message sent to each party during Round 2 of the BLS TSS keygen protocol.
type KGRound2Message2 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	DeCommitment [][]byte `protobuf:"bytes,1,rep,name=de_commitment,json=deCommitment,proto3" json:"de_commitment,omitempty"`
	Proof        [][]byte `protobuf:"bytes,2,rep,name=proof,proto3" json:"proof,omitempty"`
}

func (x *KGRound2Message2) Reset() {
	*x = KGRound2Message2{}
	if protoimpl.UnsafeEnabled {
		mi := &file_binance_tsslib_v2_protob_bls_keygen_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *KGRound2Message2) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*KGRound2Message2) ProtoMessage() {}

func (x *KGRound2Message2) ProtoReflect() protoreflect.Message {
	mi := &file_binance_tsslib_v2_protob_bls_keygen_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use KGRound2Message2.ProtoReflect.Descriptor instead.
func (*KGRound2Message2) Descriptor() ([]byte, []int) {
	return file_binance_tsslib_v2_protob_bls_keygen_proto_rawDescGZIP(), []int{2}
}

func (x *KGRound2Message2) GetDeCommitment() [][]byte {
	if x != nil {
		return x.DeCommitment
	}
	return nil
}

func (x *KGRound2Message2) GetProof() [][]byte {
	if x != nil {
		return x.Proof
	}
	return nil
}

var File_binance_tsslib_v2_protob_bls_keygen_proto protoreflect.FileDescriptor

var file_binance_tsslib_v2_protob_bls_keygen_proto_rawDesc = []byte{
	0x0a, 0x29, 0x62, 0x69, 0x6e, 0x61, 0x6e, 0x63, 0x65, 0x2f, 0x74, 0x73, 0x73, 0x6c, 0x69, 0x62,
	0x2f, 0x76, 0x32, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x2f, 0x62, 0x6c, 0x73, 0x2d, 0x6b,
	0x65, 0x79, 0x67, 0x65, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x1c, 0x62, 0x69, 0x6e,
	0x61, 0x6e, 0x63, 0x65, 0x2e, 0x74, 0x73, 0x73, 0x6c, 0x69, 0x62, 0x2e, 0x76, 0x32, 0x2e, 0x42,
	0x4c, 0x53, 0x2e, 0x6b, 0x65, 0x79, 0x67, 0x65, 0x6e, 0x22, 0x31, 0x0a, 0x0f, 0x4b, 0x47, 0x52,
	0x6f, 0x75, 0x6e, 0x64, 0x31, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x1e, 0x0a, 0x0a,
	0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c,
	0x52, 0x0a, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x22, 0x28, 0x0a, 0x10,
	0x4b, 0x47, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x32, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x31,
	0x12, 0x14, 0x0a, 0x05, 0x73, 0x68, 0x61, 0x72, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52,
	0x05, 0x73, 0x68, 0x61, 0x72, 0x65, 0x22, 0x4d, 0x0a, 0x10, 0x4b, 0x47, 0x52, 0x6f, 0x75, 0x6e,
	0x64, 0x32, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x32, 0x12, 0x23, 0x0a, 0x0d, 0x64, 0x65,
	0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x18, 0x01, 0x20, 0x03, 0x28,
	0x0c, 0x52, 0x0c, 0x64, 0x65, 0x43, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x12,
	0x14, 0x0a, 0x05, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x05,
	0x70, 0x72, 0x6f, 0x6f, 0x66, 0x42, 0x0c, 0x5a, 0x0a, 0x42, 0x4c, 0x53, 0x2f, 0x6b, 0x65, 0x79,
	0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_binance_tsslib_v2_protob_bls_keygen_proto_rawDescOnce sync.Once
	file_binance_tsslib_v2_protob_bls_keygen_proto_rawDescData = file_binance_tsslib_v2_protob_bls_keygen_proto_rawDesc
)

func file_binance_tsslib_v2_protob_bls_keygen_proto_rawDescGZIP() []byte {
	file_binance_tsslib_v2_protob_bls_keygen_proto_rawDescOnce.Do(func() {
		file_binance_tsslib_v2_protob_bls_keygen_proto_rawDescData = protoimpl.X.CompressGZIP(file_binance_tsslib_v2_protob_bls_keygen_proto_rawDescData)
	})
	return file_binance_tsslib_v2_protob_bls_keygen_proto_rawDescData
}

var file_binance_tsslib_v2_protob_bls_keygen_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_binance_tsslib_v2_protob_bls_keygen_proto_goTypes = []interface{}{
	(*KGRound1Message)(nil),  // 0: binance.tsslib.v2.BLS.keygen.KGRound1Message
	(*KGRound2Message1)(nil), // 1: binance.tsslib.v2.BLS.keygen.KGRound2Message1
	(*KGRound2Message2)(nil), // 2: binance.tsslib.v2.BLS.keygen.KGRound2Message2
}
var file_binance_tsslib_v2_protob_bls_keygen_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_binance_tsslib_v2_protob_bls_keygen_proto_init() }
func file_binance_tsslib_v2_protob_bls_keygen_proto_init() {
	if File_binance_tsslib_v2_protob_bls_keygen_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_binance_tsslib_v2_protob_bls_keygen_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*KGRound1Message); i {
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
		file_binance_tsslib_v2_protob_bls_keygen_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*KGRound2Message1); i {
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
		file_binance_tsslib_v2_protob_bls_keygen_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*KGRound2Message2); i {
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
			RawDescriptor: file_binance_tsslib_v2_protob_bls_keygen_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_binance_tsslib_v2_protob_bls_keygen_proto_goTypes,
		DependencyIndexes: file_binance_tsslib_v2_protob_bls_keygen_proto_depIdxs,
		MessageInfos:      file_binance_tsslib_v2_protob_bls_keygen_proto_msgTypes,
	}.Build()
	File_binance_tsslib_v2_protob_bls_keygen_proto = out.File
	file_binance_tsslib_v2_protob_bls_keygen_proto_rawDesc = nil
	file_binance_tsslib_v2_protob_bls_keygen_proto_goTypes = nil
	file_binance_tsslib_v2_protob_bls_keygen_proto_depIdxs = nil
}
