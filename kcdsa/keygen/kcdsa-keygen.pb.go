// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.0
// 	protoc        v3.19.4
// source: protob/kcdsa-keygen.proto

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

//
// Represents a BROADCAST message sent during Round 1 of the KCDSA TSS keygen protocol.
type KGRound1Message1 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	PaillierN   []byte `protobuf:"bytes,1,opt,name=paillier_n,json=paillierN,proto3" json:"paillier_n,omitempty"`
	NTilde      []byte `protobuf:"bytes,2,opt,name=n_tilde,json=nTilde,proto3" json:"n_tilde,omitempty"`
	H1          []byte `protobuf:"bytes,3,opt,name=h1,proto3" json:"h1,omitempty"`
	H2          []byte `protobuf:"bytes,4,opt,name=h2,proto3" json:"h2,omitempty"`
	R           []byte `protobuf:"bytes,5,opt,name=R,proto3" json:"R,omitempty"`
	X           []byte `protobuf:"bytes,6,opt,name=X,proto3" json:"X,omitempty"`
	RCommitment []byte `protobuf:"bytes,7,opt,name=r_commitment,json=rCommitment,proto3" json:"r_commitment,omitempty"`
	XCommitment []byte `protobuf:"bytes,8,opt,name=x_commitment,json=xCommitment,proto3" json:"x_commitment,omitempty"`
}

func (x *KGRound1Message1) Reset() {
	*x = KGRound1Message1{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_kcdsa_keygen_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *KGRound1Message1) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*KGRound1Message1) ProtoMessage() {}

func (x *KGRound1Message1) ProtoReflect() protoreflect.Message {
	mi := &file_protob_kcdsa_keygen_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use KGRound1Message1.ProtoReflect.Descriptor instead.
func (*KGRound1Message1) Descriptor() ([]byte, []int) {
	return file_protob_kcdsa_keygen_proto_rawDescGZIP(), []int{0}
}

func (x *KGRound1Message1) GetPaillierN() []byte {
	if x != nil {
		return x.PaillierN
	}
	return nil
}

func (x *KGRound1Message1) GetNTilde() []byte {
	if x != nil {
		return x.NTilde
	}
	return nil
}

func (x *KGRound1Message1) GetH1() []byte {
	if x != nil {
		return x.H1
	}
	return nil
}

func (x *KGRound1Message1) GetH2() []byte {
	if x != nil {
		return x.H2
	}
	return nil
}

func (x *KGRound1Message1) GetR() []byte {
	if x != nil {
		return x.R
	}
	return nil
}

func (x *KGRound1Message1) GetX() []byte {
	if x != nil {
		return x.X
	}
	return nil
}

func (x *KGRound1Message1) GetRCommitment() []byte {
	if x != nil {
		return x.RCommitment
	}
	return nil
}

func (x *KGRound1Message1) GetXCommitment() []byte {
	if x != nil {
		return x.XCommitment
	}
	return nil
}

//
// Represents a P2P message sent during Round 1 of the KCDSA TSS keygen protocol.
type KGRound2Message1 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	EncProof [][]byte `protobuf:"bytes,1,rep,name=EncProof,proto3" json:"EncProof,omitempty"`
	RShare   []byte   `protobuf:"bytes,2,opt,name=r_share,json=rShare,proto3" json:"r_share,omitempty"`
	XShare   []byte   `protobuf:"bytes,3,opt,name=x_share,json=xShare,proto3" json:"x_share,omitempty"`
}

func (x *KGRound2Message1) Reset() {
	*x = KGRound2Message1{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_kcdsa_keygen_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *KGRound2Message1) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*KGRound2Message1) ProtoMessage() {}

func (x *KGRound2Message1) ProtoReflect() protoreflect.Message {
	mi := &file_protob_kcdsa_keygen_proto_msgTypes[1]
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
	return file_protob_kcdsa_keygen_proto_rawDescGZIP(), []int{1}
}

func (x *KGRound2Message1) GetEncProof() [][]byte {
	if x != nil {
		return x.EncProof
	}
	return nil
}

func (x *KGRound2Message1) GetRShare() []byte {
	if x != nil {
		return x.RShare
	}
	return nil
}

func (x *KGRound2Message1) GetXShare() []byte {
	if x != nil {
		return x.XShare
	}
	return nil
}

//
// Represents a BROADCAST message sent to each party during Round 2 of the SCHNORR TSS keygen protocol.
type KGRound2Message2 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	RDeCommitment [][]byte `protobuf:"bytes,1,rep,name=r_de_commitment,json=rDeCommitment,proto3" json:"r_de_commitment,omitempty"`
	RProof        [][]byte `protobuf:"bytes,2,rep,name=r_proof,json=rProof,proto3" json:"r_proof,omitempty"`
	XDeCommitment [][]byte `protobuf:"bytes,3,rep,name=x_de_commitment,json=xDeCommitment,proto3" json:"x_de_commitment,omitempty"`
	XProof        [][]byte `protobuf:"bytes,4,rep,name=x_proof,json=xProof,proto3" json:"x_proof,omitempty"`
}

func (x *KGRound2Message2) Reset() {
	*x = KGRound2Message2{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_kcdsa_keygen_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *KGRound2Message2) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*KGRound2Message2) ProtoMessage() {}

func (x *KGRound2Message2) ProtoReflect() protoreflect.Message {
	mi := &file_protob_kcdsa_keygen_proto_msgTypes[2]
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
	return file_protob_kcdsa_keygen_proto_rawDescGZIP(), []int{2}
}

func (x *KGRound2Message2) GetRDeCommitment() [][]byte {
	if x != nil {
		return x.RDeCommitment
	}
	return nil
}

func (x *KGRound2Message2) GetRProof() [][]byte {
	if x != nil {
		return x.RProof
	}
	return nil
}

func (x *KGRound2Message2) GetXDeCommitment() [][]byte {
	if x != nil {
		return x.XDeCommitment
	}
	return nil
}

func (x *KGRound2Message2) GetXProof() [][]byte {
	if x != nil {
		return x.XProof
	}
	return nil
}

//
// Represents a P2P message sent to each party during Round 2 of the ECDSA TSS signing protocol.
type KGRound3Message1 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	BigXShare    [][]byte `protobuf:"bytes,1,rep,name=BigXShare,proto3" json:"BigXShare,omitempty"`
	DjiRX        []byte   `protobuf:"bytes,2,opt,name=DjiRX,proto3" json:"DjiRX,omitempty"`
	FjiRX        []byte   `protobuf:"bytes,3,opt,name=FjiRX,proto3" json:"FjiRX,omitempty"`
	AffgProofRX  [][]byte `protobuf:"bytes,4,rep,name=AffgProofRX,proto3" json:"AffgProofRX,omitempty"`
	LogstarProof [][]byte `protobuf:"bytes,5,rep,name=LogstarProof,proto3" json:"LogstarProof,omitempty"`
}

func (x *KGRound3Message1) Reset() {
	*x = KGRound3Message1{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_kcdsa_keygen_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *KGRound3Message1) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*KGRound3Message1) ProtoMessage() {}

func (x *KGRound3Message1) ProtoReflect() protoreflect.Message {
	mi := &file_protob_kcdsa_keygen_proto_msgTypes[3]
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
	return file_protob_kcdsa_keygen_proto_rawDescGZIP(), []int{3}
}

func (x *KGRound3Message1) GetBigXShare() [][]byte {
	if x != nil {
		return x.BigXShare
	}
	return nil
}

func (x *KGRound3Message1) GetDjiRX() []byte {
	if x != nil {
		return x.DjiRX
	}
	return nil
}

func (x *KGRound3Message1) GetFjiRX() []byte {
	if x != nil {
		return x.FjiRX
	}
	return nil
}

func (x *KGRound3Message1) GetAffgProofRX() [][]byte {
	if x != nil {
		return x.AffgProofRX
	}
	return nil
}

func (x *KGRound3Message1) GetLogstarProof() [][]byte {
	if x != nil {
		return x.LogstarProof
	}
	return nil
}

//
// Represents a P2P message sent to all parties during Round 3 of the ECDSA TSS signing protocol.
type KGRound4Message1 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	RXShare      []byte   `protobuf:"bytes,1,opt,name=RXShare,proto3" json:"RXShare,omitempty"`
	BigRXShare   [][]byte `protobuf:"bytes,2,rep,name=BigRXShare,proto3" json:"BigRXShare,omitempty"`
	ProofLogstar [][]byte `protobuf:"bytes,3,rep,name=ProofLogstar,proto3" json:"ProofLogstar,omitempty"`
}

func (x *KGRound4Message1) Reset() {
	*x = KGRound4Message1{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_kcdsa_keygen_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *KGRound4Message1) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*KGRound4Message1) ProtoMessage() {}

func (x *KGRound4Message1) ProtoReflect() protoreflect.Message {
	mi := &file_protob_kcdsa_keygen_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use KGRound4Message1.ProtoReflect.Descriptor instead.
func (*KGRound4Message1) Descriptor() ([]byte, []int) {
	return file_protob_kcdsa_keygen_proto_rawDescGZIP(), []int{4}
}

func (x *KGRound4Message1) GetRXShare() []byte {
	if x != nil {
		return x.RXShare
	}
	return nil
}

func (x *KGRound4Message1) GetBigRXShare() [][]byte {
	if x != nil {
		return x.BigRXShare
	}
	return nil
}

func (x *KGRound4Message1) GetProofLogstar() [][]byte {
	if x != nil {
		return x.ProofLogstar
	}
	return nil
}

var File_protob_kcdsa_keygen_proto protoreflect.FileDescriptor

var file_protob_kcdsa_keygen_proto_rawDesc = []byte{
	0x0a, 0x19, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x2f, 0x6b, 0x63, 0x64, 0x73, 0x61, 0x2d, 0x6b,
	0x65, 0x79, 0x67, 0x65, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x1b, 0x62, 0x69, 0x6e,
	0x61, 0x6e, 0x63, 0x65, 0x2e, 0x74, 0x73, 0x73, 0x6c, 0x69, 0x62, 0x2e, 0x6b, 0x63, 0x64, 0x73,
	0x61, 0x2e, 0x6b, 0x65, 0x79, 0x67, 0x65, 0x6e, 0x22, 0xcc, 0x01, 0x0a, 0x10, 0x4b, 0x47, 0x52,
	0x6f, 0x75, 0x6e, 0x64, 0x31, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x31, 0x12, 0x1d, 0x0a,
	0x0a, 0x70, 0x61, 0x69, 0x6c, 0x6c, 0x69, 0x65, 0x72, 0x5f, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x09, 0x70, 0x61, 0x69, 0x6c, 0x6c, 0x69, 0x65, 0x72, 0x4e, 0x12, 0x17, 0x0a, 0x07,
	0x6e, 0x5f, 0x74, 0x69, 0x6c, 0x64, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x06, 0x6e,
	0x54, 0x69, 0x6c, 0x64, 0x65, 0x12, 0x0e, 0x0a, 0x02, 0x68, 0x31, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x02, 0x68, 0x31, 0x12, 0x0e, 0x0a, 0x02, 0x68, 0x32, 0x18, 0x04, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x02, 0x68, 0x32, 0x12, 0x0c, 0x0a, 0x01, 0x52, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0c,
	0x52, 0x01, 0x52, 0x12, 0x0c, 0x0a, 0x01, 0x58, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x01,
	0x58, 0x12, 0x21, 0x0a, 0x0c, 0x72, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e,
	0x74, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0b, 0x72, 0x43, 0x6f, 0x6d, 0x6d, 0x69, 0x74,
	0x6d, 0x65, 0x6e, 0x74, 0x12, 0x21, 0x0a, 0x0c, 0x78, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74,
	0x6d, 0x65, 0x6e, 0x74, 0x18, 0x08, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0b, 0x78, 0x43, 0x6f, 0x6d,
	0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x22, 0x60, 0x0a, 0x10, 0x4b, 0x47, 0x52, 0x6f, 0x75,
	0x6e, 0x64, 0x32, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x31, 0x12, 0x1a, 0x0a, 0x08, 0x45,
	0x6e, 0x63, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x08, 0x45,
	0x6e, 0x63, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x12, 0x17, 0x0a, 0x07, 0x72, 0x5f, 0x73, 0x68, 0x61,
	0x72, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x06, 0x72, 0x53, 0x68, 0x61, 0x72, 0x65,
	0x12, 0x17, 0x0a, 0x07, 0x78, 0x5f, 0x73, 0x68, 0x61, 0x72, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x06, 0x78, 0x53, 0x68, 0x61, 0x72, 0x65, 0x22, 0x94, 0x01, 0x0a, 0x10, 0x4b, 0x47,
	0x52, 0x6f, 0x75, 0x6e, 0x64, 0x32, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x32, 0x12, 0x26,
	0x0a, 0x0f, 0x72, 0x5f, 0x64, 0x65, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e,
	0x74, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x0d, 0x72, 0x44, 0x65, 0x43, 0x6f, 0x6d, 0x6d,
	0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x12, 0x17, 0x0a, 0x07, 0x72, 0x5f, 0x70, 0x72, 0x6f, 0x6f,
	0x66, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x06, 0x72, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x12,
	0x26, 0x0a, 0x0f, 0x78, 0x5f, 0x64, 0x65, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65,
	0x6e, 0x74, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x0d, 0x78, 0x44, 0x65, 0x43, 0x6f, 0x6d,
	0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x12, 0x17, 0x0a, 0x07, 0x78, 0x5f, 0x70, 0x72, 0x6f,
	0x6f, 0x66, 0x18, 0x04, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x06, 0x78, 0x50, 0x72, 0x6f, 0x6f, 0x66,
	0x22, 0xa2, 0x01, 0x0a, 0x10, 0x4b, 0x47, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x33, 0x4d, 0x65, 0x73,
	0x73, 0x61, 0x67, 0x65, 0x31, 0x12, 0x1c, 0x0a, 0x09, 0x42, 0x69, 0x67, 0x58, 0x53, 0x68, 0x61,
	0x72, 0x65, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x09, 0x42, 0x69, 0x67, 0x58, 0x53, 0x68,
	0x61, 0x72, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x44, 0x6a, 0x69, 0x52, 0x58, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x05, 0x44, 0x6a, 0x69, 0x52, 0x58, 0x12, 0x14, 0x0a, 0x05, 0x46, 0x6a, 0x69,
	0x52, 0x58, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x05, 0x46, 0x6a, 0x69, 0x52, 0x58, 0x12,
	0x20, 0x0a, 0x0b, 0x41, 0x66, 0x66, 0x67, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x52, 0x58, 0x18, 0x04,
	0x20, 0x03, 0x28, 0x0c, 0x52, 0x0b, 0x41, 0x66, 0x66, 0x67, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x52,
	0x58, 0x12, 0x22, 0x0a, 0x0c, 0x4c, 0x6f, 0x67, 0x73, 0x74, 0x61, 0x72, 0x50, 0x72, 0x6f, 0x6f,
	0x66, 0x18, 0x05, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x0c, 0x4c, 0x6f, 0x67, 0x73, 0x74, 0x61, 0x72,
	0x50, 0x72, 0x6f, 0x6f, 0x66, 0x22, 0x70, 0x0a, 0x10, 0x4b, 0x47, 0x52, 0x6f, 0x75, 0x6e, 0x64,
	0x34, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x31, 0x12, 0x18, 0x0a, 0x07, 0x52, 0x58, 0x53,
	0x68, 0x61, 0x72, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x07, 0x52, 0x58, 0x53, 0x68,
	0x61, 0x72, 0x65, 0x12, 0x1e, 0x0a, 0x0a, 0x42, 0x69, 0x67, 0x52, 0x58, 0x53, 0x68, 0x61, 0x72,
	0x65, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x0a, 0x42, 0x69, 0x67, 0x52, 0x58, 0x53, 0x68,
	0x61, 0x72, 0x65, 0x12, 0x22, 0x0a, 0x0c, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x4c, 0x6f, 0x67, 0x73,
	0x74, 0x61, 0x72, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x0c, 0x50, 0x72, 0x6f, 0x6f, 0x66,
	0x4c, 0x6f, 0x67, 0x73, 0x74, 0x61, 0x72, 0x42, 0x0e, 0x5a, 0x0c, 0x6b, 0x63, 0x64, 0x73, 0x61,
	0x2f, 0x6b, 0x65, 0x79, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_protob_kcdsa_keygen_proto_rawDescOnce sync.Once
	file_protob_kcdsa_keygen_proto_rawDescData = file_protob_kcdsa_keygen_proto_rawDesc
)

func file_protob_kcdsa_keygen_proto_rawDescGZIP() []byte {
	file_protob_kcdsa_keygen_proto_rawDescOnce.Do(func() {
		file_protob_kcdsa_keygen_proto_rawDescData = protoimpl.X.CompressGZIP(file_protob_kcdsa_keygen_proto_rawDescData)
	})
	return file_protob_kcdsa_keygen_proto_rawDescData
}

var file_protob_kcdsa_keygen_proto_msgTypes = make([]protoimpl.MessageInfo, 5)
var file_protob_kcdsa_keygen_proto_goTypes = []interface{}{
	(*KGRound1Message1)(nil), // 0: binance.tsslib.kcdsa.keygen.KGRound1Message1
	(*KGRound2Message1)(nil), // 1: binance.tsslib.kcdsa.keygen.KGRound2Message1
	(*KGRound2Message2)(nil), // 2: binance.tsslib.kcdsa.keygen.KGRound2Message2
	(*KGRound3Message1)(nil), // 3: binance.tsslib.kcdsa.keygen.KGRound3Message1
	(*KGRound4Message1)(nil), // 4: binance.tsslib.kcdsa.keygen.KGRound4Message1
}
var file_protob_kcdsa_keygen_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_protob_kcdsa_keygen_proto_init() }
func file_protob_kcdsa_keygen_proto_init() {
	if File_protob_kcdsa_keygen_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_protob_kcdsa_keygen_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*KGRound1Message1); i {
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
		file_protob_kcdsa_keygen_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
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
		file_protob_kcdsa_keygen_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
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
		file_protob_kcdsa_keygen_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
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
		file_protob_kcdsa_keygen_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*KGRound4Message1); i {
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
			RawDescriptor: file_protob_kcdsa_keygen_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   5,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_protob_kcdsa_keygen_proto_goTypes,
		DependencyIndexes: file_protob_kcdsa_keygen_proto_depIdxs,
		MessageInfos:      file_protob_kcdsa_keygen_proto_msgTypes,
	}.Build()
	File_protob_kcdsa_keygen_proto = out.File
	file_protob_kcdsa_keygen_proto_rawDesc = nil
	file_protob_kcdsa_keygen_proto_goTypes = nil
	file_protob_kcdsa_keygen_proto_depIdxs = nil
}
