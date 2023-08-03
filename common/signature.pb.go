// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.31.0
// 	protoc        v3.20.3
// source: protob/signature.proto

package common

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

// Container for output signatures, mostly used for marshalling this data structure to a mobile app
type SignatureData struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Signature []byte `protobuf:"bytes,1,opt,name=signature,proto3" json:"signature,omitempty"`
	// Ethereum-style recovery byte; only the first byte is relevant
	SignatureRecovery []byte `protobuf:"bytes,2,opt,name=signature_recovery,json=signatureRecovery,proto3" json:"signature_recovery,omitempty"`
	// Signature components R, S
	R []byte `protobuf:"bytes,3,opt,name=r,proto3" json:"r,omitempty"`
	S []byte `protobuf:"bytes,4,opt,name=s,proto3" json:"s,omitempty"`
	// M represents the original message digest that was signed M
	M []byte `protobuf:"bytes,5,opt,name=m,proto3" json:"m,omitempty"`
}

func (x *SignatureData) Reset() {
	*x = SignatureData{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_signature_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignatureData) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignatureData) ProtoMessage() {}

func (x *SignatureData) ProtoReflect() protoreflect.Message {
	mi := &file_protob_signature_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignatureData.ProtoReflect.Descriptor instead.
func (*SignatureData) Descriptor() ([]byte, []int) {
	return file_protob_signature_proto_rawDescGZIP(), []int{0}
}

func (x *SignatureData) GetSignature() []byte {
	if x != nil {
		return x.Signature
	}
	return nil
}

func (x *SignatureData) GetSignatureRecovery() []byte {
	if x != nil {
		return x.SignatureRecovery
	}
	return nil
}

func (x *SignatureData) GetR() []byte {
	if x != nil {
		return x.R
	}
	return nil
}

func (x *SignatureData) GetS() []byte {
	if x != nil {
		return x.S
	}
	return nil
}

func (x *SignatureData) GetM() []byte {
	if x != nil {
		return x.M
	}
	return nil
}

var File_protob_signature_proto protoreflect.FileDescriptor

var file_protob_signature_proto_rawDesc = []byte{
	0x0a, 0x16, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x2f, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75,
	0x72, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0e, 0x62, 0x69, 0x6e, 0x61, 0x6e, 0x63,
	0x65, 0x2e, 0x74, 0x73, 0x73, 0x6c, 0x69, 0x62, 0x22, 0x86, 0x01, 0x0a, 0x0d, 0x53, 0x69, 0x67,
	0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x44, 0x61, 0x74, 0x61, 0x12, 0x1c, 0x0a, 0x09, 0x73, 0x69,
	0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x09, 0x73,
	0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x12, 0x2d, 0x0a, 0x12, 0x73, 0x69, 0x67, 0x6e,
	0x61, 0x74, 0x75, 0x72, 0x65, 0x5f, 0x72, 0x65, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x0c, 0x52, 0x11, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x52,
	0x65, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x12, 0x0c, 0x0a, 0x01, 0x72, 0x18, 0x03, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x01, 0x72, 0x12, 0x0c, 0x0a, 0x01, 0x73, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0c,
	0x52, 0x01, 0x73, 0x12, 0x0c, 0x0a, 0x01, 0x6d, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x01,
	0x6d, 0x42, 0x0a, 0x5a, 0x08, 0x2e, 0x2f, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x62, 0x06, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_protob_signature_proto_rawDescOnce sync.Once
	file_protob_signature_proto_rawDescData = file_protob_signature_proto_rawDesc
)

func file_protob_signature_proto_rawDescGZIP() []byte {
	file_protob_signature_proto_rawDescOnce.Do(func() {
		file_protob_signature_proto_rawDescData = protoimpl.X.CompressGZIP(file_protob_signature_proto_rawDescData)
	})
	return file_protob_signature_proto_rawDescData
}

var file_protob_signature_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_protob_signature_proto_goTypes = []interface{}{
	(*SignatureData)(nil), // 0: binance.tsslib.SignatureData
}
var file_protob_signature_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_protob_signature_proto_init() }
func file_protob_signature_proto_init() {
	if File_protob_signature_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_protob_signature_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignatureData); i {
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
			RawDescriptor: file_protob_signature_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_protob_signature_proto_goTypes,
		DependencyIndexes: file_protob_signature_proto_depIdxs,
		MessageInfos:      file_protob_signature_proto_msgTypes,
	}.Build()
	File_protob_signature_proto = out.File
	file_protob_signature_proto_rawDesc = nil
	file_protob_signature_proto_goTypes = nil
	file_protob_signature_proto_depIdxs = nil
}
