// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.26.0-devel
// 	protoc        v3.17.3
// source: protob/ecdsa-presigning.proto

package presigning

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

//
// Represents a P2P message sent to each party during Round 1 of the ECDSA TSS signing protocol.
type PreSignRound1Message struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	K        []byte   `protobuf:"bytes,1,opt,name=K,proto3" json:"K,omitempty"`
	G        []byte   `protobuf:"bytes,2,opt,name=G,proto3" json:"G,omitempty"`
	EncProof [][]byte `protobuf:"bytes,3,rep,name=EncProof,proto3" json:"EncProof,omitempty"`
}

func (x *PreSignRound1Message) Reset() {
	*x = PreSignRound1Message{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_ecdsa_presigning_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PreSignRound1Message) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PreSignRound1Message) ProtoMessage() {}

func (x *PreSignRound1Message) ProtoReflect() protoreflect.Message {
	mi := &file_protob_ecdsa_presigning_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PreSignRound1Message.ProtoReflect.Descriptor instead.
func (*PreSignRound1Message) Descriptor() ([]byte, []int) {
	return file_protob_ecdsa_presigning_proto_rawDescGZIP(), []int{0}
}

func (x *PreSignRound1Message) GetK() []byte {
	if x != nil {
		return x.K
	}
	return nil
}

func (x *PreSignRound1Message) GetG() []byte {
	if x != nil {
		return x.G
	}
	return nil
}

func (x *PreSignRound1Message) GetEncProof() [][]byte {
	if x != nil {
		return x.EncProof
	}
	return nil
}

//
// Represents a P2P message sent to each party during Round 2 of the ECDSA TSS signing protocol.
type PreSignRound2Message struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	BigGammaShare  [][]byte `protobuf:"bytes,1,rep,name=BigGammaShare,proto3" json:"BigGammaShare,omitempty"`
	DjiDelta       []byte   `protobuf:"bytes,2,opt,name=DjiDelta,proto3" json:"DjiDelta,omitempty"`
	FjiDelta       []byte   `protobuf:"bytes,3,opt,name=FjiDelta,proto3" json:"FjiDelta,omitempty"`
	DjiChi         []byte   `protobuf:"bytes,4,opt,name=DjiChi,proto3" json:"DjiChi,omitempty"`
	FjiChi         []byte   `protobuf:"bytes,5,opt,name=FjiChi,proto3" json:"FjiChi,omitempty"`
	AffgProofDelta [][]byte `protobuf:"bytes,6,rep,name=AffgProofDelta,proto3" json:"AffgProofDelta,omitempty"`
	AffgProofChi   [][]byte `protobuf:"bytes,7,rep,name=AffgProofChi,proto3" json:"AffgProofChi,omitempty"`
	LogstarProof   [][]byte `protobuf:"bytes,8,rep,name=LogstarProof,proto3" json:"LogstarProof,omitempty"`
}

func (x *PreSignRound2Message) Reset() {
	*x = PreSignRound2Message{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_ecdsa_presigning_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PreSignRound2Message) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PreSignRound2Message) ProtoMessage() {}

func (x *PreSignRound2Message) ProtoReflect() protoreflect.Message {
	mi := &file_protob_ecdsa_presigning_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PreSignRound2Message.ProtoReflect.Descriptor instead.
func (*PreSignRound2Message) Descriptor() ([]byte, []int) {
	return file_protob_ecdsa_presigning_proto_rawDescGZIP(), []int{1}
}

func (x *PreSignRound2Message) GetBigGammaShare() [][]byte {
	if x != nil {
		return x.BigGammaShare
	}
	return nil
}

func (x *PreSignRound2Message) GetDjiDelta() []byte {
	if x != nil {
		return x.DjiDelta
	}
	return nil
}

func (x *PreSignRound2Message) GetFjiDelta() []byte {
	if x != nil {
		return x.FjiDelta
	}
	return nil
}

func (x *PreSignRound2Message) GetDjiChi() []byte {
	if x != nil {
		return x.DjiChi
	}
	return nil
}

func (x *PreSignRound2Message) GetFjiChi() []byte {
	if x != nil {
		return x.FjiChi
	}
	return nil
}

func (x *PreSignRound2Message) GetAffgProofDelta() [][]byte {
	if x != nil {
		return x.AffgProofDelta
	}
	return nil
}

func (x *PreSignRound2Message) GetAffgProofChi() [][]byte {
	if x != nil {
		return x.AffgProofChi
	}
	return nil
}

func (x *PreSignRound2Message) GetLogstarProof() [][]byte {
	if x != nil {
		return x.LogstarProof
	}
	return nil
}

//
// Represents a P2P message sent to all parties during Round 3 of the ECDSA TSS signing protocol.
type PreSignRound3Message struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	DeltaShare    []byte   `protobuf:"bytes,1,opt,name=DeltaShare,proto3" json:"DeltaShare,omitempty"`
	BigDeltaShare [][]byte `protobuf:"bytes,2,rep,name=BigDeltaShare,proto3" json:"BigDeltaShare,omitempty"`
	ProofLogstar  [][]byte `protobuf:"bytes,3,rep,name=ProofLogstar,proto3" json:"ProofLogstar,omitempty"`
}

func (x *PreSignRound3Message) Reset() {
	*x = PreSignRound3Message{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_ecdsa_presigning_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PreSignRound3Message) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PreSignRound3Message) ProtoMessage() {}

func (x *PreSignRound3Message) ProtoReflect() protoreflect.Message {
	mi := &file_protob_ecdsa_presigning_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PreSignRound3Message.ProtoReflect.Descriptor instead.
func (*PreSignRound3Message) Descriptor() ([]byte, []int) {
	return file_protob_ecdsa_presigning_proto_rawDescGZIP(), []int{2}
}

func (x *PreSignRound3Message) GetDeltaShare() []byte {
	if x != nil {
		return x.DeltaShare
	}
	return nil
}

func (x *PreSignRound3Message) GetBigDeltaShare() [][]byte {
	if x != nil {
		return x.BigDeltaShare
	}
	return nil
}

func (x *PreSignRound3Message) GetProofLogstar() [][]byte {
	if x != nil {
		return x.ProofLogstar
	}
	return nil
}

type IdentificationRound6Message struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	H             []byte   `protobuf:"bytes,1,opt,name=H,proto3" json:"H,omitempty"`
	MulProof      [][]byte `protobuf:"bytes,2,rep,name=MulProof,proto3" json:"MulProof,omitempty"`
	DeltaShareEnc []byte   `protobuf:"bytes,3,opt,name=DeltaShareEnc,proto3" json:"DeltaShareEnc,omitempty"`
	DecProof      [][]byte `protobuf:"bytes,4,rep,name=DecProof,proto3" json:"DecProof,omitempty"`
}

func (x *IdentificationRound6Message) Reset() {
	*x = IdentificationRound6Message{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_ecdsa_presigning_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *IdentificationRound6Message) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*IdentificationRound6Message) ProtoMessage() {}

func (x *IdentificationRound6Message) ProtoReflect() protoreflect.Message {
	mi := &file_protob_ecdsa_presigning_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use IdentificationRound6Message.ProtoReflect.Descriptor instead.
func (*IdentificationRound6Message) Descriptor() ([]byte, []int) {
	return file_protob_ecdsa_presigning_proto_rawDescGZIP(), []int{3}
}

func (x *IdentificationRound6Message) GetH() []byte {
	if x != nil {
		return x.H
	}
	return nil
}

func (x *IdentificationRound6Message) GetMulProof() [][]byte {
	if x != nil {
		return x.MulProof
	}
	return nil
}

func (x *IdentificationRound6Message) GetDeltaShareEnc() []byte {
	if x != nil {
		return x.DeltaShareEnc
	}
	return nil
}

func (x *IdentificationRound6Message) GetDecProof() [][]byte {
	if x != nil {
		return x.DecProof
	}
	return nil
}

//
// Container for output presignatures
type PreSignatureData struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Index    int32    `protobuf:"varint,1,opt,name=index,proto3" json:"index,omitempty"`
	Ssid     []byte   `protobuf:"bytes,2,opt,name=ssid,proto3" json:"ssid,omitempty"`
	BigR     [][]byte `protobuf:"bytes,3,rep,name=bigR,proto3" json:"bigR,omitempty"`
	KShare   []byte   `protobuf:"bytes,4,opt,name=kShare,proto3" json:"kShare,omitempty"`
	ChiShare []byte   `protobuf:"bytes,5,opt,name=chiShare,proto3" json:"chiShare,omitempty"`
}

func (x *PreSignatureData) Reset() {
	*x = PreSignatureData{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_ecdsa_presigning_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PreSignatureData) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PreSignatureData) ProtoMessage() {}

func (x *PreSignatureData) ProtoReflect() protoreflect.Message {
	mi := &file_protob_ecdsa_presigning_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PreSignatureData.ProtoReflect.Descriptor instead.
func (*PreSignatureData) Descriptor() ([]byte, []int) {
	return file_protob_ecdsa_presigning_proto_rawDescGZIP(), []int{4}
}

func (x *PreSignatureData) GetIndex() int32 {
	if x != nil {
		return x.Index
	}
	return 0
}

func (x *PreSignatureData) GetSsid() []byte {
	if x != nil {
		return x.Ssid
	}
	return nil
}

func (x *PreSignatureData) GetBigR() [][]byte {
	if x != nil {
		return x.BigR
	}
	return nil
}

func (x *PreSignatureData) GetKShare() []byte {
	if x != nil {
		return x.KShare
	}
	return nil
}

func (x *PreSignatureData) GetChiShare() []byte {
	if x != nil {
		return x.ChiShare
	}
	return nil
}

var File_protob_ecdsa_presigning_proto protoreflect.FileDescriptor

var file_protob_ecdsa_presigning_proto_rawDesc = []byte{
	0x0a, 0x1d, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x2f, 0x65, 0x63, 0x64, 0x73, 0x61, 0x2d, 0x70,
	0x72, 0x65, 0x73, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x1f, 0x62, 0x69, 0x6e, 0x61, 0x6e, 0x63, 0x65, 0x2e, 0x74, 0x73, 0x73, 0x6c, 0x69, 0x62, 0x2e,
	0x65, 0x63, 0x64, 0x73, 0x61, 0x2e, 0x70, 0x72, 0x65, 0x73, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67,
	0x22, 0x4e, 0x0a, 0x14, 0x50, 0x72, 0x65, 0x53, 0x69, 0x67, 0x6e, 0x52, 0x6f, 0x75, 0x6e, 0x64,
	0x31, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x0c, 0x0a, 0x01, 0x4b, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0c, 0x52, 0x01, 0x4b, 0x12, 0x0c, 0x0a, 0x01, 0x47, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x01, 0x47, 0x12, 0x1a, 0x0a, 0x08, 0x45, 0x6e, 0x63, 0x50, 0x72, 0x6f, 0x6f, 0x66,
	0x18, 0x03, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x08, 0x45, 0x6e, 0x63, 0x50, 0x72, 0x6f, 0x6f, 0x66,
	0x22, 0x94, 0x02, 0x0a, 0x14, 0x50, 0x72, 0x65, 0x53, 0x69, 0x67, 0x6e, 0x52, 0x6f, 0x75, 0x6e,
	0x64, 0x32, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x24, 0x0a, 0x0d, 0x42, 0x69, 0x67,
	0x47, 0x61, 0x6d, 0x6d, 0x61, 0x53, 0x68, 0x61, 0x72, 0x65, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0c,
	0x52, 0x0d, 0x42, 0x69, 0x67, 0x47, 0x61, 0x6d, 0x6d, 0x61, 0x53, 0x68, 0x61, 0x72, 0x65, 0x12,
	0x1a, 0x0a, 0x08, 0x44, 0x6a, 0x69, 0x44, 0x65, 0x6c, 0x74, 0x61, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x08, 0x44, 0x6a, 0x69, 0x44, 0x65, 0x6c, 0x74, 0x61, 0x12, 0x1a, 0x0a, 0x08, 0x46,
	0x6a, 0x69, 0x44, 0x65, 0x6c, 0x74, 0x61, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x08, 0x46,
	0x6a, 0x69, 0x44, 0x65, 0x6c, 0x74, 0x61, 0x12, 0x16, 0x0a, 0x06, 0x44, 0x6a, 0x69, 0x43, 0x68,
	0x69, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x06, 0x44, 0x6a, 0x69, 0x43, 0x68, 0x69, 0x12,
	0x16, 0x0a, 0x06, 0x46, 0x6a, 0x69, 0x43, 0x68, 0x69, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0c, 0x52,
	0x06, 0x46, 0x6a, 0x69, 0x43, 0x68, 0x69, 0x12, 0x26, 0x0a, 0x0e, 0x41, 0x66, 0x66, 0x67, 0x50,
	0x72, 0x6f, 0x6f, 0x66, 0x44, 0x65, 0x6c, 0x74, 0x61, 0x18, 0x06, 0x20, 0x03, 0x28, 0x0c, 0x52,
	0x0e, 0x41, 0x66, 0x66, 0x67, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x44, 0x65, 0x6c, 0x74, 0x61, 0x12,
	0x22, 0x0a, 0x0c, 0x41, 0x66, 0x66, 0x67, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x43, 0x68, 0x69, 0x18,
	0x07, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x0c, 0x41, 0x66, 0x66, 0x67, 0x50, 0x72, 0x6f, 0x6f, 0x66,
	0x43, 0x68, 0x69, 0x12, 0x22, 0x0a, 0x0c, 0x4c, 0x6f, 0x67, 0x73, 0x74, 0x61, 0x72, 0x50, 0x72,
	0x6f, 0x6f, 0x66, 0x18, 0x08, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x0c, 0x4c, 0x6f, 0x67, 0x73, 0x74,
	0x61, 0x72, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x22, 0x80, 0x01, 0x0a, 0x14, 0x50, 0x72, 0x65, 0x53,
	0x69, 0x67, 0x6e, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x33, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65,
	0x12, 0x1e, 0x0a, 0x0a, 0x44, 0x65, 0x6c, 0x74, 0x61, 0x53, 0x68, 0x61, 0x72, 0x65, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x0c, 0x52, 0x0a, 0x44, 0x65, 0x6c, 0x74, 0x61, 0x53, 0x68, 0x61, 0x72, 0x65,
	0x12, 0x24, 0x0a, 0x0d, 0x42, 0x69, 0x67, 0x44, 0x65, 0x6c, 0x74, 0x61, 0x53, 0x68, 0x61, 0x72,
	0x65, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x0d, 0x42, 0x69, 0x67, 0x44, 0x65, 0x6c, 0x74,
	0x61, 0x53, 0x68, 0x61, 0x72, 0x65, 0x12, 0x22, 0x0a, 0x0c, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x4c,
	0x6f, 0x67, 0x73, 0x74, 0x61, 0x72, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x0c, 0x50, 0x72,
	0x6f, 0x6f, 0x66, 0x4c, 0x6f, 0x67, 0x73, 0x74, 0x61, 0x72, 0x22, 0x89, 0x01, 0x0a, 0x1b, 0x49,
	0x64, 0x65, 0x6e, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x6f, 0x75,
	0x6e, 0x64, 0x36, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x0c, 0x0a, 0x01, 0x48, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x01, 0x48, 0x12, 0x1a, 0x0a, 0x08, 0x4d, 0x75, 0x6c, 0x50,
	0x72, 0x6f, 0x6f, 0x66, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x08, 0x4d, 0x75, 0x6c, 0x50,
	0x72, 0x6f, 0x6f, 0x66, 0x12, 0x24, 0x0a, 0x0d, 0x44, 0x65, 0x6c, 0x74, 0x61, 0x53, 0x68, 0x61,
	0x72, 0x65, 0x45, 0x6e, 0x63, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0d, 0x44, 0x65, 0x6c,
	0x74, 0x61, 0x53, 0x68, 0x61, 0x72, 0x65, 0x45, 0x6e, 0x63, 0x12, 0x1a, 0x0a, 0x08, 0x44, 0x65,
	0x63, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x18, 0x04, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x08, 0x44, 0x65,
	0x63, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x22, 0x84, 0x01, 0x0a, 0x10, 0x50, 0x72, 0x65, 0x53, 0x69,
	0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x44, 0x61, 0x74, 0x61, 0x12, 0x14, 0x0a, 0x05, 0x69,
	0x6e, 0x64, 0x65, 0x78, 0x18, 0x01, 0x20, 0x01, 0x28, 0x05, 0x52, 0x05, 0x69, 0x6e, 0x64, 0x65,
	0x78, 0x12, 0x12, 0x0a, 0x04, 0x73, 0x73, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52,
	0x04, 0x73, 0x73, 0x69, 0x64, 0x12, 0x12, 0x0a, 0x04, 0x62, 0x69, 0x67, 0x52, 0x18, 0x03, 0x20,
	0x03, 0x28, 0x0c, 0x52, 0x04, 0x62, 0x69, 0x67, 0x52, 0x12, 0x16, 0x0a, 0x06, 0x6b, 0x53, 0x68,
	0x61, 0x72, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x06, 0x6b, 0x53, 0x68, 0x61, 0x72,
	0x65, 0x12, 0x1a, 0x0a, 0x08, 0x63, 0x68, 0x69, 0x53, 0x68, 0x61, 0x72, 0x65, 0x18, 0x05, 0x20,
	0x01, 0x28, 0x0c, 0x52, 0x08, 0x63, 0x68, 0x69, 0x53, 0x68, 0x61, 0x72, 0x65, 0x42, 0x12, 0x5a,
	0x10, 0x65, 0x63, 0x64, 0x73, 0x61, 0x2f, 0x70, 0x72, 0x65, 0x73, 0x69, 0x67, 0x6e, 0x69, 0x6e,
	0x67, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_protob_ecdsa_presigning_proto_rawDescOnce sync.Once
	file_protob_ecdsa_presigning_proto_rawDescData = file_protob_ecdsa_presigning_proto_rawDesc
)

func file_protob_ecdsa_presigning_proto_rawDescGZIP() []byte {
	file_protob_ecdsa_presigning_proto_rawDescOnce.Do(func() {
		file_protob_ecdsa_presigning_proto_rawDescData = protoimpl.X.CompressGZIP(file_protob_ecdsa_presigning_proto_rawDescData)
	})
	return file_protob_ecdsa_presigning_proto_rawDescData
}

var file_protob_ecdsa_presigning_proto_msgTypes = make([]protoimpl.MessageInfo, 5)
var file_protob_ecdsa_presigning_proto_goTypes = []interface{}{
	(*PreSignRound1Message)(nil),        // 0: binance.tsslib.ecdsa.presigning.PreSignRound1Message
	(*PreSignRound2Message)(nil),        // 1: binance.tsslib.ecdsa.presigning.PreSignRound2Message
	(*PreSignRound3Message)(nil),        // 2: binance.tsslib.ecdsa.presigning.PreSignRound3Message
	(*IdentificationRound6Message)(nil), // 3: binance.tsslib.ecdsa.presigning.IdentificationRound6Message
	(*PreSignatureData)(nil),            // 4: binance.tsslib.ecdsa.presigning.PreSignatureData
}
var file_protob_ecdsa_presigning_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_protob_ecdsa_presigning_proto_init() }
func file_protob_ecdsa_presigning_proto_init() {
	if File_protob_ecdsa_presigning_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_protob_ecdsa_presigning_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PreSignRound1Message); i {
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
		file_protob_ecdsa_presigning_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PreSignRound2Message); i {
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
		file_protob_ecdsa_presigning_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PreSignRound3Message); i {
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
		file_protob_ecdsa_presigning_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*IdentificationRound6Message); i {
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
		file_protob_ecdsa_presigning_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PreSignatureData); i {
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
			RawDescriptor: file_protob_ecdsa_presigning_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   5,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_protob_ecdsa_presigning_proto_goTypes,
		DependencyIndexes: file_protob_ecdsa_presigning_proto_depIdxs,
		MessageInfos:      file_protob_ecdsa_presigning_proto_msgTypes,
	}.Build()
	File_protob_ecdsa_presigning_proto = out.File
	file_protob_ecdsa_presigning_proto_rawDesc = nil
	file_protob_ecdsa_presigning_proto_goTypes = nil
	file_protob_ecdsa_presigning_proto_depIdxs = nil
}
