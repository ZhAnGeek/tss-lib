// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.31.0
// 	protoc        v4.25.3
// source: binance/tsslib/v2/protob/kcdsa-resharing.proto

package resharing

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

// The Round 1 data is broadcast to peers of the All Committee in this message.
type DGRound1MessageNewParty struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	PaillierN []byte `protobuf:"bytes,1,opt,name=paillier_n,json=paillierN,proto3" json:"paillier_n,omitempty"`
	NTilde    []byte `protobuf:"bytes,2,opt,name=n_tilde,json=nTilde,proto3" json:"n_tilde,omitempty"`
	H1        []byte `protobuf:"bytes,3,opt,name=h1,proto3" json:"h1,omitempty"`
	H2        []byte `protobuf:"bytes,4,opt,name=h2,proto3" json:"h2,omitempty"`
}

func (x *DGRound1MessageNewParty) Reset() {
	*x = DGRound1MessageNewParty{}
	if protoimpl.UnsafeEnabled {
		mi := &file_binance_tsslib_v2_protob_kcdsa_resharing_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DGRound1MessageNewParty) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DGRound1MessageNewParty) ProtoMessage() {}

func (x *DGRound1MessageNewParty) ProtoReflect() protoreflect.Message {
	mi := &file_binance_tsslib_v2_protob_kcdsa_resharing_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DGRound1MessageNewParty.ProtoReflect.Descriptor instead.
func (*DGRound1MessageNewParty) Descriptor() ([]byte, []int) {
	return file_binance_tsslib_v2_protob_kcdsa_resharing_proto_rawDescGZIP(), []int{0}
}

func (x *DGRound1MessageNewParty) GetPaillierN() []byte {
	if x != nil {
		return x.PaillierN
	}
	return nil
}

func (x *DGRound1MessageNewParty) GetNTilde() []byte {
	if x != nil {
		return x.NTilde
	}
	return nil
}

func (x *DGRound1MessageNewParty) GetH1() []byte {
	if x != nil {
		return x.H1
	}
	return nil
}

func (x *DGRound1MessageNewParty) GetH2() []byte {
	if x != nil {
		return x.H2
	}
	return nil
}

// The Round 1 data is broadcast to peers of the New Committee in this message.
type DGRound1Message struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	PubX        []byte `protobuf:"bytes,1,opt,name=pub_x,json=pubX,proto3" json:"pub_x,omitempty"`
	PubY        []byte `protobuf:"bytes,2,opt,name=pub_y,json=pubY,proto3" json:"pub_y,omitempty"`
	PubXSchnorr []byte `protobuf:"bytes,3,opt,name=pub_x_schnorr,json=pubXSchnorr,proto3" json:"pub_x_schnorr,omitempty"`
	PubYSchnorr []byte `protobuf:"bytes,4,opt,name=pub_y_schnorr,json=pubYSchnorr,proto3" json:"pub_y_schnorr,omitempty"`
	VCommitment []byte `protobuf:"bytes,5,opt,name=v_commitment,json=vCommitment,proto3" json:"v_commitment,omitempty"`
	Ssid        []byte `protobuf:"bytes,6,opt,name=ssid,proto3" json:"ssid,omitempty"`
}

func (x *DGRound1Message) Reset() {
	*x = DGRound1Message{}
	if protoimpl.UnsafeEnabled {
		mi := &file_binance_tsslib_v2_protob_kcdsa_resharing_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DGRound1Message) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DGRound1Message) ProtoMessage() {}

func (x *DGRound1Message) ProtoReflect() protoreflect.Message {
	mi := &file_binance_tsslib_v2_protob_kcdsa_resharing_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DGRound1Message.ProtoReflect.Descriptor instead.
func (*DGRound1Message) Descriptor() ([]byte, []int) {
	return file_binance_tsslib_v2_protob_kcdsa_resharing_proto_rawDescGZIP(), []int{1}
}

func (x *DGRound1Message) GetPubX() []byte {
	if x != nil {
		return x.PubX
	}
	return nil
}

func (x *DGRound1Message) GetPubY() []byte {
	if x != nil {
		return x.PubY
	}
	return nil
}

func (x *DGRound1Message) GetPubXSchnorr() []byte {
	if x != nil {
		return x.PubXSchnorr
	}
	return nil
}

func (x *DGRound1Message) GetPubYSchnorr() []byte {
	if x != nil {
		return x.PubYSchnorr
	}
	return nil
}

func (x *DGRound1Message) GetVCommitment() []byte {
	if x != nil {
		return x.VCommitment
	}
	return nil
}

func (x *DGRound1Message) GetSsid() []byte {
	if x != nil {
		return x.Ssid
	}
	return nil
}

// The Round 2 "ACK" is broadcast to peers of the Old Committee in this message.
type DGRound2Message struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *DGRound2Message) Reset() {
	*x = DGRound2Message{}
	if protoimpl.UnsafeEnabled {
		mi := &file_binance_tsslib_v2_protob_kcdsa_resharing_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DGRound2Message) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DGRound2Message) ProtoMessage() {}

func (x *DGRound2Message) ProtoReflect() protoreflect.Message {
	mi := &file_binance_tsslib_v2_protob_kcdsa_resharing_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DGRound2Message.ProtoReflect.Descriptor instead.
func (*DGRound2Message) Descriptor() ([]byte, []int) {
	return file_binance_tsslib_v2_protob_kcdsa_resharing_proto_rawDescGZIP(), []int{2}
}

// The Round 2 Pallier proofs is broadcast to peers of the All Committee in this message.
type DGRound2Message2 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	PrmProof [][]byte `protobuf:"bytes,1,rep,name=prm_proof,json=prmProof,proto3" json:"prm_proof,omitempty"`
	ModProof [][]byte `protobuf:"bytes,2,rep,name=mod_proof,json=modProof,proto3" json:"mod_proof,omitempty"`
}

func (x *DGRound2Message2) Reset() {
	*x = DGRound2Message2{}
	if protoimpl.UnsafeEnabled {
		mi := &file_binance_tsslib_v2_protob_kcdsa_resharing_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DGRound2Message2) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DGRound2Message2) ProtoMessage() {}

func (x *DGRound2Message2) ProtoReflect() protoreflect.Message {
	mi := &file_binance_tsslib_v2_protob_kcdsa_resharing_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DGRound2Message2.ProtoReflect.Descriptor instead.
func (*DGRound2Message2) Descriptor() ([]byte, []int) {
	return file_binance_tsslib_v2_protob_kcdsa_resharing_proto_rawDescGZIP(), []int{3}
}

func (x *DGRound2Message2) GetPrmProof() [][]byte {
	if x != nil {
		return x.PrmProof
	}
	return nil
}

func (x *DGRound2Message2) GetModProof() [][]byte {
	if x != nil {
		return x.ModProof
	}
	return nil
}

// The Round 3 data is sent to peers of the New Committee in this message.
type DGRound3Message1 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Share []byte `protobuf:"bytes,1,opt,name=share,proto3" json:"share,omitempty"`
}

func (x *DGRound3Message1) Reset() {
	*x = DGRound3Message1{}
	if protoimpl.UnsafeEnabled {
		mi := &file_binance_tsslib_v2_protob_kcdsa_resharing_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DGRound3Message1) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DGRound3Message1) ProtoMessage() {}

func (x *DGRound3Message1) ProtoReflect() protoreflect.Message {
	mi := &file_binance_tsslib_v2_protob_kcdsa_resharing_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DGRound3Message1.ProtoReflect.Descriptor instead.
func (*DGRound3Message1) Descriptor() ([]byte, []int) {
	return file_binance_tsslib_v2_protob_kcdsa_resharing_proto_rawDescGZIP(), []int{4}
}

func (x *DGRound3Message1) GetShare() []byte {
	if x != nil {
		return x.Share
	}
	return nil
}

// The Round 3 data is broadcast to peers of the New Committee in this message.
type DGRound3Message2 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	VDecommitment [][]byte `protobuf:"bytes,1,rep,name=v_decommitment,json=vDecommitment,proto3" json:"v_decommitment,omitempty"`
}

func (x *DGRound3Message2) Reset() {
	*x = DGRound3Message2{}
	if protoimpl.UnsafeEnabled {
		mi := &file_binance_tsslib_v2_protob_kcdsa_resharing_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DGRound3Message2) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DGRound3Message2) ProtoMessage() {}

func (x *DGRound3Message2) ProtoReflect() protoreflect.Message {
	mi := &file_binance_tsslib_v2_protob_kcdsa_resharing_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DGRound3Message2.ProtoReflect.Descriptor instead.
func (*DGRound3Message2) Descriptor() ([]byte, []int) {
	return file_binance_tsslib_v2_protob_kcdsa_resharing_proto_rawDescGZIP(), []int{5}
}

func (x *DGRound3Message2) GetVDecommitment() [][]byte {
	if x != nil {
		return x.VDecommitment
	}
	return nil
}

// The Round 4 "FacProof" is p2p to peers of the New Committees from the New Committee in this message.
type DGRound4Message1 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	FacProof [][]byte `protobuf:"bytes,1,rep,name=fac_proof,json=facProof,proto3" json:"fac_proof,omitempty"`
}

func (x *DGRound4Message1) Reset() {
	*x = DGRound4Message1{}
	if protoimpl.UnsafeEnabled {
		mi := &file_binance_tsslib_v2_protob_kcdsa_resharing_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DGRound4Message1) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DGRound4Message1) ProtoMessage() {}

func (x *DGRound4Message1) ProtoReflect() protoreflect.Message {
	mi := &file_binance_tsslib_v2_protob_kcdsa_resharing_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DGRound4Message1.ProtoReflect.Descriptor instead.
func (*DGRound4Message1) Descriptor() ([]byte, []int) {
	return file_binance_tsslib_v2_protob_kcdsa_resharing_proto_rawDescGZIP(), []int{6}
}

func (x *DGRound4Message1) GetFacProof() [][]byte {
	if x != nil {
		return x.FacProof
	}
	return nil
}

// The Round 4 "ACK" is broadcast to peers of the Old and New Committees from the New Committee in this message.
type DGRound4Message2 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *DGRound4Message2) Reset() {
	*x = DGRound4Message2{}
	if protoimpl.UnsafeEnabled {
		mi := &file_binance_tsslib_v2_protob_kcdsa_resharing_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DGRound4Message2) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DGRound4Message2) ProtoMessage() {}

func (x *DGRound4Message2) ProtoReflect() protoreflect.Message {
	mi := &file_binance_tsslib_v2_protob_kcdsa_resharing_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DGRound4Message2.ProtoReflect.Descriptor instead.
func (*DGRound4Message2) Descriptor() ([]byte, []int) {
	return file_binance_tsslib_v2_protob_kcdsa_resharing_proto_rawDescGZIP(), []int{7}
}

var File_binance_tsslib_v2_protob_kcdsa_resharing_proto protoreflect.FileDescriptor

var file_binance_tsslib_v2_protob_kcdsa_resharing_proto_rawDesc = []byte{
	0x0a, 0x2e, 0x62, 0x69, 0x6e, 0x61, 0x6e, 0x63, 0x65, 0x2f, 0x74, 0x73, 0x73, 0x6c, 0x69, 0x62,
	0x2f, 0x76, 0x32, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x2f, 0x6b, 0x63, 0x64, 0x73, 0x61,
	0x2d, 0x72, 0x65, 0x73, 0x68, 0x61, 0x72, 0x69, 0x6e, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x12, 0x21, 0x62, 0x69, 0x6e, 0x61, 0x6e, 0x63, 0x65, 0x2e, 0x74, 0x73, 0x73, 0x6c, 0x69, 0x62,
	0x2e, 0x76, 0x32, 0x2e, 0x6b, 0x63, 0x64, 0x73, 0x61, 0x2e, 0x72, 0x65, 0x73, 0x68, 0x61, 0x72,
	0x69, 0x6e, 0x67, 0x22, 0x71, 0x0a, 0x17, 0x44, 0x47, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x31, 0x4d,
	0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x4e, 0x65, 0x77, 0x50, 0x61, 0x72, 0x74, 0x79, 0x12, 0x1d,
	0x0a, 0x0a, 0x70, 0x61, 0x69, 0x6c, 0x6c, 0x69, 0x65, 0x72, 0x5f, 0x6e, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x09, 0x70, 0x61, 0x69, 0x6c, 0x6c, 0x69, 0x65, 0x72, 0x4e, 0x12, 0x17, 0x0a,
	0x07, 0x6e, 0x5f, 0x74, 0x69, 0x6c, 0x64, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x06,
	0x6e, 0x54, 0x69, 0x6c, 0x64, 0x65, 0x12, 0x0e, 0x0a, 0x02, 0x68, 0x31, 0x18, 0x03, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x02, 0x68, 0x31, 0x12, 0x0e, 0x0a, 0x02, 0x68, 0x32, 0x18, 0x04, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x02, 0x68, 0x32, 0x22, 0xba, 0x01, 0x0a, 0x0f, 0x44, 0x47, 0x52, 0x6f, 0x75,
	0x6e, 0x64, 0x31, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x13, 0x0a, 0x05, 0x70, 0x75,
	0x62, 0x5f, 0x78, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x04, 0x70, 0x75, 0x62, 0x58, 0x12,
	0x13, 0x0a, 0x05, 0x70, 0x75, 0x62, 0x5f, 0x79, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x04,
	0x70, 0x75, 0x62, 0x59, 0x12, 0x22, 0x0a, 0x0d, 0x70, 0x75, 0x62, 0x5f, 0x78, 0x5f, 0x73, 0x63,
	0x68, 0x6e, 0x6f, 0x72, 0x72, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0b, 0x70, 0x75, 0x62,
	0x58, 0x53, 0x63, 0x68, 0x6e, 0x6f, 0x72, 0x72, 0x12, 0x22, 0x0a, 0x0d, 0x70, 0x75, 0x62, 0x5f,
	0x79, 0x5f, 0x73, 0x63, 0x68, 0x6e, 0x6f, 0x72, 0x72, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0c, 0x52,
	0x0b, 0x70, 0x75, 0x62, 0x59, 0x53, 0x63, 0x68, 0x6e, 0x6f, 0x72, 0x72, 0x12, 0x21, 0x0a, 0x0c,
	0x76, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x18, 0x05, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x0b, 0x76, 0x43, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x12,
	0x12, 0x0a, 0x04, 0x73, 0x73, 0x69, 0x64, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x04, 0x73,
	0x73, 0x69, 0x64, 0x22, 0x11, 0x0a, 0x0f, 0x44, 0x47, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x32, 0x4d,
	0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x22, 0x4c, 0x0a, 0x10, 0x44, 0x47, 0x52, 0x6f, 0x75, 0x6e,
	0x64, 0x32, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x32, 0x12, 0x1b, 0x0a, 0x09, 0x70, 0x72,
	0x6d, 0x5f, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x08, 0x70,
	0x72, 0x6d, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x12, 0x1b, 0x0a, 0x09, 0x6d, 0x6f, 0x64, 0x5f, 0x70,
	0x72, 0x6f, 0x6f, 0x66, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x08, 0x6d, 0x6f, 0x64, 0x50,
	0x72, 0x6f, 0x6f, 0x66, 0x22, 0x28, 0x0a, 0x10, 0x44, 0x47, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x33,
	0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x31, 0x12, 0x14, 0x0a, 0x05, 0x73, 0x68, 0x61, 0x72,
	0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x05, 0x73, 0x68, 0x61, 0x72, 0x65, 0x22, 0x39,
	0x0a, 0x10, 0x44, 0x47, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x33, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67,
	0x65, 0x32, 0x12, 0x25, 0x0a, 0x0e, 0x76, 0x5f, 0x64, 0x65, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74,
	0x6d, 0x65, 0x6e, 0x74, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x0d, 0x76, 0x44, 0x65, 0x63,
	0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x22, 0x2f, 0x0a, 0x10, 0x44, 0x47, 0x52,
	0x6f, 0x75, 0x6e, 0x64, 0x34, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x31, 0x12, 0x1b, 0x0a,
	0x09, 0x66, 0x61, 0x63, 0x5f, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0c,
	0x52, 0x08, 0x66, 0x61, 0x63, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x22, 0x12, 0x0a, 0x10, 0x44, 0x47,
	0x52, 0x6f, 0x75, 0x6e, 0x64, 0x34, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x32, 0x42, 0x11,
	0x5a, 0x0f, 0x6b, 0x63, 0x64, 0x73, 0x61, 0x2f, 0x72, 0x65, 0x73, 0x68, 0x61, 0x72, 0x69, 0x6e,
	0x67, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_binance_tsslib_v2_protob_kcdsa_resharing_proto_rawDescOnce sync.Once
	file_binance_tsslib_v2_protob_kcdsa_resharing_proto_rawDescData = file_binance_tsslib_v2_protob_kcdsa_resharing_proto_rawDesc
)

func file_binance_tsslib_v2_protob_kcdsa_resharing_proto_rawDescGZIP() []byte {
	file_binance_tsslib_v2_protob_kcdsa_resharing_proto_rawDescOnce.Do(func() {
		file_binance_tsslib_v2_protob_kcdsa_resharing_proto_rawDescData = protoimpl.X.CompressGZIP(file_binance_tsslib_v2_protob_kcdsa_resharing_proto_rawDescData)
	})
	return file_binance_tsslib_v2_protob_kcdsa_resharing_proto_rawDescData
}

var file_binance_tsslib_v2_protob_kcdsa_resharing_proto_msgTypes = make([]protoimpl.MessageInfo, 8)
var file_binance_tsslib_v2_protob_kcdsa_resharing_proto_goTypes = []interface{}{
	(*DGRound1MessageNewParty)(nil), // 0: binance.tsslib.v2.kcdsa.resharing.DGRound1MessageNewParty
	(*DGRound1Message)(nil),         // 1: binance.tsslib.v2.kcdsa.resharing.DGRound1Message
	(*DGRound2Message)(nil),         // 2: binance.tsslib.v2.kcdsa.resharing.DGRound2Message
	(*DGRound2Message2)(nil),        // 3: binance.tsslib.v2.kcdsa.resharing.DGRound2Message2
	(*DGRound3Message1)(nil),        // 4: binance.tsslib.v2.kcdsa.resharing.DGRound3Message1
	(*DGRound3Message2)(nil),        // 5: binance.tsslib.v2.kcdsa.resharing.DGRound3Message2
	(*DGRound4Message1)(nil),        // 6: binance.tsslib.v2.kcdsa.resharing.DGRound4Message1
	(*DGRound4Message2)(nil),        // 7: binance.tsslib.v2.kcdsa.resharing.DGRound4Message2
}
var file_binance_tsslib_v2_protob_kcdsa_resharing_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_binance_tsslib_v2_protob_kcdsa_resharing_proto_init() }
func file_binance_tsslib_v2_protob_kcdsa_resharing_proto_init() {
	if File_binance_tsslib_v2_protob_kcdsa_resharing_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_binance_tsslib_v2_protob_kcdsa_resharing_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DGRound1MessageNewParty); i {
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
		file_binance_tsslib_v2_protob_kcdsa_resharing_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DGRound1Message); i {
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
		file_binance_tsslib_v2_protob_kcdsa_resharing_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DGRound2Message); i {
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
		file_binance_tsslib_v2_protob_kcdsa_resharing_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DGRound2Message2); i {
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
		file_binance_tsslib_v2_protob_kcdsa_resharing_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DGRound3Message1); i {
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
		file_binance_tsslib_v2_protob_kcdsa_resharing_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DGRound3Message2); i {
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
		file_binance_tsslib_v2_protob_kcdsa_resharing_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DGRound4Message1); i {
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
		file_binance_tsslib_v2_protob_kcdsa_resharing_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DGRound4Message2); i {
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
			RawDescriptor: file_binance_tsslib_v2_protob_kcdsa_resharing_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   8,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_binance_tsslib_v2_protob_kcdsa_resharing_proto_goTypes,
		DependencyIndexes: file_binance_tsslib_v2_protob_kcdsa_resharing_proto_depIdxs,
		MessageInfos:      file_binance_tsslib_v2_protob_kcdsa_resharing_proto_msgTypes,
	}.Build()
	File_binance_tsslib_v2_protob_kcdsa_resharing_proto = out.File
	file_binance_tsslib_v2_protob_kcdsa_resharing_proto_rawDesc = nil
	file_binance_tsslib_v2_protob_kcdsa_resharing_proto_goTypes = nil
	file_binance_tsslib_v2_protob_kcdsa_resharing_proto_depIdxs = nil
}
