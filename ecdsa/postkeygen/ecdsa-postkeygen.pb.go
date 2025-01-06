// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.31.0
// 	protoc        v4.25.3
// source: binance/tsslib/v2/protob/ecdsa-postkeygen.proto

package postkeygen

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

type KGRound1MessageAck struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *KGRound1MessageAck) Reset() {
	*x = KGRound1MessageAck{}
	if protoimpl.UnsafeEnabled {
		mi := &file_binance_tsslib_v2_protob_ecdsa_postkeygen_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *KGRound1MessageAck) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*KGRound1MessageAck) ProtoMessage() {}

func (x *KGRound1MessageAck) ProtoReflect() protoreflect.Message {
	mi := &file_binance_tsslib_v2_protob_ecdsa_postkeygen_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use KGRound1MessageAck.ProtoReflect.Descriptor instead.
func (*KGRound1MessageAck) Descriptor() ([]byte, []int) {
	return file_binance_tsslib_v2_protob_ecdsa_postkeygen_proto_rawDescGZIP(), []int{0}
}

// Represents a BROADCAST message sent during Round 1 of the KCDSA TSS keygen protocol.
type KGRound2Message1 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	PaillierN []byte   `protobuf:"bytes,1,opt,name=PaillierN,proto3" json:"PaillierN,omitempty"`
	NTilde    []byte   `protobuf:"bytes,2,opt,name=NTilde,proto3" json:"NTilde,omitempty"`
	H1        []byte   `protobuf:"bytes,3,opt,name=H1,proto3" json:"H1,omitempty"`
	H2        []byte   `protobuf:"bytes,4,opt,name=H2,proto3" json:"H2,omitempty"`
	PrmProof  [][]byte `protobuf:"bytes,5,rep,name=PrmProof,proto3" json:"PrmProof,omitempty"`
	ModProof  [][]byte `protobuf:"bytes,6,rep,name=ModProof,proto3" json:"ModProof,omitempty"`
}

func (x *KGRound2Message1) Reset() {
	*x = KGRound2Message1{}
	if protoimpl.UnsafeEnabled {
		mi := &file_binance_tsslib_v2_protob_ecdsa_postkeygen_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *KGRound2Message1) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*KGRound2Message1) ProtoMessage() {}

func (x *KGRound2Message1) ProtoReflect() protoreflect.Message {
	mi := &file_binance_tsslib_v2_protob_ecdsa_postkeygen_proto_msgTypes[1]
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
	return file_binance_tsslib_v2_protob_ecdsa_postkeygen_proto_rawDescGZIP(), []int{1}
}

func (x *KGRound2Message1) GetPaillierN() []byte {
	if x != nil {
		return x.PaillierN
	}
	return nil
}

func (x *KGRound2Message1) GetNTilde() []byte {
	if x != nil {
		return x.NTilde
	}
	return nil
}

func (x *KGRound2Message1) GetH1() []byte {
	if x != nil {
		return x.H1
	}
	return nil
}

func (x *KGRound2Message1) GetH2() []byte {
	if x != nil {
		return x.H2
	}
	return nil
}

func (x *KGRound2Message1) GetPrmProof() [][]byte {
	if x != nil {
		return x.PrmProof
	}
	return nil
}

func (x *KGRound2Message1) GetModProof() [][]byte {
	if x != nil {
		return x.ModProof
	}
	return nil
}

// Represents a P2P message sent during Round 2 of the KCDSA TSS keygen protocol.
type KGRound3Message1 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	FacProof [][]byte `protobuf:"bytes,1,rep,name=FacProof,proto3" json:"FacProof,omitempty"`
}

func (x *KGRound3Message1) Reset() {
	*x = KGRound3Message1{}
	if protoimpl.UnsafeEnabled {
		mi := &file_binance_tsslib_v2_protob_ecdsa_postkeygen_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *KGRound3Message1) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*KGRound3Message1) ProtoMessage() {}

func (x *KGRound3Message1) ProtoReflect() protoreflect.Message {
	mi := &file_binance_tsslib_v2_protob_ecdsa_postkeygen_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use KGRound3Message1.ProtoReflect.Descriptor instead.
func (*KGRound3Message1) Descriptor() ([]byte, []int) {
	return file_binance_tsslib_v2_protob_ecdsa_postkeygen_proto_rawDescGZIP(), []int{2}
}

func (x *KGRound3Message1) GetFacProof() [][]byte {
	if x != nil {
		return x.FacProof
	}
	return nil
}

var File_binance_tsslib_v2_protob_ecdsa_postkeygen_proto protoreflect.FileDescriptor

var file_binance_tsslib_v2_protob_ecdsa_postkeygen_proto_rawDesc = []byte{
	0x0a, 0x2f, 0x62, 0x69, 0x6e, 0x61, 0x6e, 0x63, 0x65, 0x2f, 0x74, 0x73, 0x73, 0x6c, 0x69, 0x62,
	0x2f, 0x76, 0x32, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x2f, 0x65, 0x63, 0x64, 0x73, 0x61,
	0x2d, 0x70, 0x6f, 0x73, 0x74, 0x6b, 0x65, 0x79, 0x67, 0x65, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x12, 0x22, 0x62, 0x69, 0x6e, 0x61, 0x6e, 0x63, 0x65, 0x2e, 0x74, 0x73, 0x73, 0x6c, 0x69,
	0x62, 0x2e, 0x76, 0x32, 0x2e, 0x65, 0x63, 0x64, 0x73, 0x61, 0x2e, 0x70, 0x6f, 0x73, 0x74, 0x6b,
	0x65, 0x79, 0x67, 0x65, 0x6e, 0x22, 0x14, 0x0a, 0x12, 0x4b, 0x47, 0x52, 0x6f, 0x75, 0x6e, 0x64,
	0x31, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x41, 0x63, 0x6b, 0x22, 0xa0, 0x01, 0x0a, 0x10,
	0x4b, 0x47, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x32, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x31,
	0x12, 0x1c, 0x0a, 0x09, 0x50, 0x61, 0x69, 0x6c, 0x6c, 0x69, 0x65, 0x72, 0x4e, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0c, 0x52, 0x09, 0x50, 0x61, 0x69, 0x6c, 0x6c, 0x69, 0x65, 0x72, 0x4e, 0x12, 0x16,
	0x0a, 0x06, 0x4e, 0x54, 0x69, 0x6c, 0x64, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x06,
	0x4e, 0x54, 0x69, 0x6c, 0x64, 0x65, 0x12, 0x0e, 0x0a, 0x02, 0x48, 0x31, 0x18, 0x03, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x02, 0x48, 0x31, 0x12, 0x0e, 0x0a, 0x02, 0x48, 0x32, 0x18, 0x04, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x02, 0x48, 0x32, 0x12, 0x1a, 0x0a, 0x08, 0x50, 0x72, 0x6d, 0x50, 0x72, 0x6f,
	0x6f, 0x66, 0x18, 0x05, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x08, 0x50, 0x72, 0x6d, 0x50, 0x72, 0x6f,
	0x6f, 0x66, 0x12, 0x1a, 0x0a, 0x08, 0x4d, 0x6f, 0x64, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x18, 0x06,
	0x20, 0x03, 0x28, 0x0c, 0x52, 0x08, 0x4d, 0x6f, 0x64, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x22, 0x2e,
	0x0a, 0x10, 0x4b, 0x47, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x33, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67,
	0x65, 0x31, 0x12, 0x1a, 0x0a, 0x08, 0x46, 0x61, 0x63, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x18, 0x01,
	0x20, 0x03, 0x28, 0x0c, 0x52, 0x08, 0x46, 0x61, 0x63, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x42, 0x12,
	0x5a, 0x10, 0x65, 0x63, 0x64, 0x73, 0x61, 0x2f, 0x70, 0x6f, 0x73, 0x74, 0x6b, 0x65, 0x79, 0x67,
	0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_binance_tsslib_v2_protob_ecdsa_postkeygen_proto_rawDescOnce sync.Once
	file_binance_tsslib_v2_protob_ecdsa_postkeygen_proto_rawDescData = file_binance_tsslib_v2_protob_ecdsa_postkeygen_proto_rawDesc
)

func file_binance_tsslib_v2_protob_ecdsa_postkeygen_proto_rawDescGZIP() []byte {
	file_binance_tsslib_v2_protob_ecdsa_postkeygen_proto_rawDescOnce.Do(func() {
		file_binance_tsslib_v2_protob_ecdsa_postkeygen_proto_rawDescData = protoimpl.X.CompressGZIP(file_binance_tsslib_v2_protob_ecdsa_postkeygen_proto_rawDescData)
	})
	return file_binance_tsslib_v2_protob_ecdsa_postkeygen_proto_rawDescData
}

var file_binance_tsslib_v2_protob_ecdsa_postkeygen_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_binance_tsslib_v2_protob_ecdsa_postkeygen_proto_goTypes = []interface{}{
	(*KGRound1MessageAck)(nil), // 0: binance.tsslib.v2.ecdsa.postkeygen.KGRound1MessageAck
	(*KGRound2Message1)(nil),   // 1: binance.tsslib.v2.ecdsa.postkeygen.KGRound2Message1
	(*KGRound3Message1)(nil),   // 2: binance.tsslib.v2.ecdsa.postkeygen.KGRound3Message1
}
var file_binance_tsslib_v2_protob_ecdsa_postkeygen_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_binance_tsslib_v2_protob_ecdsa_postkeygen_proto_init() }
func file_binance_tsslib_v2_protob_ecdsa_postkeygen_proto_init() {
	if File_binance_tsslib_v2_protob_ecdsa_postkeygen_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_binance_tsslib_v2_protob_ecdsa_postkeygen_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*KGRound1MessageAck); i {
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
		file_binance_tsslib_v2_protob_ecdsa_postkeygen_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
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
		file_binance_tsslib_v2_protob_ecdsa_postkeygen_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*KGRound3Message1); i {
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
			RawDescriptor: file_binance_tsslib_v2_protob_ecdsa_postkeygen_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_binance_tsslib_v2_protob_ecdsa_postkeygen_proto_goTypes,
		DependencyIndexes: file_binance_tsslib_v2_protob_ecdsa_postkeygen_proto_depIdxs,
		MessageInfos:      file_binance_tsslib_v2_protob_ecdsa_postkeygen_proto_msgTypes,
	}.Build()
	File_binance_tsslib_v2_protob_ecdsa_postkeygen_proto = out.File
	file_binance_tsslib_v2_protob_ecdsa_postkeygen_proto_rawDesc = nil
	file_binance_tsslib_v2_protob_ecdsa_postkeygen_proto_goTypes = nil
	file_binance_tsslib_v2_protob_ecdsa_postkeygen_proto_depIdxs = nil
}
