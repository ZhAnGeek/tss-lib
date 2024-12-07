// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.31.0
// 	protoc        v4.25.3
// source: binance/tsslib/v2/protob/aleo-signing.proto

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

// Represents a BROADCAST message sent to all parties during Round 1 of the Aleo TSS signing protocol.
type SignRound1Message struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Commitment  []byte   `protobuf:"bytes,1,opt,name=commitment,proto3" json:"commitment,omitempty"`
	PointVSkSig [][]byte `protobuf:"bytes,2,rep,name=pointV_sk_sig,json=pointVSkSig,proto3" json:"pointV_sk_sig,omitempty"`
	ProofVSkSig [][]byte `protobuf:"bytes,3,rep,name=proofV_sk_sig,json=proofVSkSig,proto3" json:"proofV_sk_sig,omitempty"`
	PointVRSig  [][]byte `protobuf:"bytes,4,rep,name=pointV_r_sig,json=pointVRSig,proto3" json:"pointV_r_sig,omitempty"`
	ProofVRSig  [][]byte `protobuf:"bytes,5,rep,name=proofV_r_sig,json=proofVRSig,proto3" json:"proofV_r_sig,omitempty"`
}

func (x *SignRound1Message) Reset() {
	*x = SignRound1Message{}
	if protoimpl.UnsafeEnabled {
		mi := &file_binance_tsslib_v2_protob_aleo_signing_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignRound1Message) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignRound1Message) ProtoMessage() {}

func (x *SignRound1Message) ProtoReflect() protoreflect.Message {
	mi := &file_binance_tsslib_v2_protob_aleo_signing_proto_msgTypes[0]
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
	return file_binance_tsslib_v2_protob_aleo_signing_proto_rawDescGZIP(), []int{0}
}

func (x *SignRound1Message) GetCommitment() []byte {
	if x != nil {
		return x.Commitment
	}
	return nil
}

func (x *SignRound1Message) GetPointVSkSig() [][]byte {
	if x != nil {
		return x.PointVSkSig
	}
	return nil
}

func (x *SignRound1Message) GetProofVSkSig() [][]byte {
	if x != nil {
		return x.ProofVSkSig
	}
	return nil
}

func (x *SignRound1Message) GetPointVRSig() [][]byte {
	if x != nil {
		return x.PointVRSig
	}
	return nil
}

func (x *SignRound1Message) GetProofVRSig() [][]byte {
	if x != nil {
		return x.ProofVRSig
	}
	return nil
}

// Represents a BROADCAST message sent to all parties during Round 2 of the Aleo TSS signing protocol.
type SignRound2Message struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	DeCommitment [][]byte `protobuf:"bytes,1,rep,name=de_commitment,json=deCommitment,proto3" json:"de_commitment,omitempty"`
	ProofD       [][]byte `protobuf:"bytes,2,rep,name=proofD,proto3" json:"proofD,omitempty"`
	ProofE       [][]byte `protobuf:"bytes,3,rep,name=proofE,proto3" json:"proofE,omitempty"`
	SkTag        []byte   `protobuf:"bytes,4,opt,name=sk_tag,json=skTag,proto3" json:"sk_tag,omitempty"`
}

func (x *SignRound2Message) Reset() {
	*x = SignRound2Message{}
	if protoimpl.UnsafeEnabled {
		mi := &file_binance_tsslib_v2_protob_aleo_signing_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignRound2Message) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignRound2Message) ProtoMessage() {}

func (x *SignRound2Message) ProtoReflect() protoreflect.Message {
	mi := &file_binance_tsslib_v2_protob_aleo_signing_proto_msgTypes[1]
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
	return file_binance_tsslib_v2_protob_aleo_signing_proto_rawDescGZIP(), []int{1}
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

func (x *SignRound2Message) GetSkTag() []byte {
	if x != nil {
		return x.SkTag
	}
	return nil
}

// Represents a BROADCAST message sent to all parties during Round 3 of the Aleo TSS signing protocol.
type SignRound3Message struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ShareList [][]byte `protobuf:"bytes,1,rep,name=share_list,json=shareList,proto3" json:"share_list,omitempty"`
	ProofList [][]byte `protobuf:"bytes,2,rep,name=proof_list,json=proofList,proto3" json:"proof_list,omitempty"`
}

func (x *SignRound3Message) Reset() {
	*x = SignRound3Message{}
	if protoimpl.UnsafeEnabled {
		mi := &file_binance_tsslib_v2_protob_aleo_signing_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignRound3Message) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignRound3Message) ProtoMessage() {}

func (x *SignRound3Message) ProtoReflect() protoreflect.Message {
	mi := &file_binance_tsslib_v2_protob_aleo_signing_proto_msgTypes[2]
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
	return file_binance_tsslib_v2_protob_aleo_signing_proto_rawDescGZIP(), []int{2}
}

func (x *SignRound3Message) GetShareList() [][]byte {
	if x != nil {
		return x.ShareList
	}
	return nil
}

func (x *SignRound3Message) GetProofList() [][]byte {
	if x != nil {
		return x.ProofList
	}
	return nil
}

// Represents a BROADCAST message sent to all parties during Round 3 of the Aleo TSS signing protocol.
type SignRound4Message struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ResponseShare []byte `protobuf:"bytes,1,opt,name=response_share,json=responseShare,proto3" json:"response_share,omitempty"`
}

func (x *SignRound4Message) Reset() {
	*x = SignRound4Message{}
	if protoimpl.UnsafeEnabled {
		mi := &file_binance_tsslib_v2_protob_aleo_signing_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignRound4Message) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignRound4Message) ProtoMessage() {}

func (x *SignRound4Message) ProtoReflect() protoreflect.Message {
	mi := &file_binance_tsslib_v2_protob_aleo_signing_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignRound4Message.ProtoReflect.Descriptor instead.
func (*SignRound4Message) Descriptor() ([]byte, []int) {
	return file_binance_tsslib_v2_protob_aleo_signing_proto_rawDescGZIP(), []int{3}
}

func (x *SignRound4Message) GetResponseShare() []byte {
	if x != nil {
		return x.ResponseShare
	}
	return nil
}

type RequestOut struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Challenge []byte `protobuf:"bytes,1,opt,name=challenge,proto3" json:"challenge,omitempty"`
	Response  []byte `protobuf:"bytes,2,opt,name=response,proto3" json:"response,omitempty"`
	SkTag     []byte `protobuf:"bytes,3,opt,name=sk_tag,json=skTag,proto3" json:"sk_tag,omitempty"`
	Tvk       []byte `protobuf:"bytes,4,opt,name=tvk,proto3" json:"tvk,omitempty"`
	Tcm       []byte `protobuf:"bytes,5,opt,name=tcm,proto3" json:"tcm,omitempty"`
	Scm       []byte `protobuf:"bytes,6,opt,name=scm,proto3" json:"scm,omitempty"`
}

func (x *RequestOut) Reset() {
	*x = RequestOut{}
	if protoimpl.UnsafeEnabled {
		mi := &file_binance_tsslib_v2_protob_aleo_signing_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RequestOut) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RequestOut) ProtoMessage() {}

func (x *RequestOut) ProtoReflect() protoreflect.Message {
	mi := &file_binance_tsslib_v2_protob_aleo_signing_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RequestOut.ProtoReflect.Descriptor instead.
func (*RequestOut) Descriptor() ([]byte, []int) {
	return file_binance_tsslib_v2_protob_aleo_signing_proto_rawDescGZIP(), []int{4}
}

func (x *RequestOut) GetChallenge() []byte {
	if x != nil {
		return x.Challenge
	}
	return nil
}

func (x *RequestOut) GetResponse() []byte {
	if x != nil {
		return x.Response
	}
	return nil
}

func (x *RequestOut) GetSkTag() []byte {
	if x != nil {
		return x.SkTag
	}
	return nil
}

func (x *RequestOut) GetTvk() []byte {
	if x != nil {
		return x.Tvk
	}
	return nil
}

func (x *RequestOut) GetTcm() []byte {
	if x != nil {
		return x.Tcm
	}
	return nil
}

func (x *RequestOut) GetScm() []byte {
	if x != nil {
		return x.Scm
	}
	return nil
}

type SDataOut struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Tvk       []byte   `protobuf:"bytes,1,opt,name=tvk,proto3" json:"tvk,omitempty"`
	SkTag     []byte   `protobuf:"bytes,2,opt,name=sk_tag,json=skTag,proto3" json:"sk_tag,omitempty"`
	GR        [][]byte `protobuf:"bytes,3,rep,name=g_r,json=gR,proto3" json:"g_r,omitempty"`
	HRList    [][]byte `protobuf:"bytes,4,rep,name=h_r_list,json=hRList,proto3" json:"h_r_list,omitempty"`
	GammaList [][]byte `protobuf:"bytes,5,rep,name=gamma_list,json=gammaList,proto3" json:"gamma_list,omitempty"`
}

func (x *SDataOut) Reset() {
	*x = SDataOut{}
	if protoimpl.UnsafeEnabled {
		mi := &file_binance_tsslib_v2_protob_aleo_signing_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SDataOut) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SDataOut) ProtoMessage() {}

func (x *SDataOut) ProtoReflect() protoreflect.Message {
	mi := &file_binance_tsslib_v2_protob_aleo_signing_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SDataOut.ProtoReflect.Descriptor instead.
func (*SDataOut) Descriptor() ([]byte, []int) {
	return file_binance_tsslib_v2_protob_aleo_signing_proto_rawDescGZIP(), []int{5}
}

func (x *SDataOut) GetTvk() []byte {
	if x != nil {
		return x.Tvk
	}
	return nil
}

func (x *SDataOut) GetSkTag() []byte {
	if x != nil {
		return x.SkTag
	}
	return nil
}

func (x *SDataOut) GetGR() [][]byte {
	if x != nil {
		return x.GR
	}
	return nil
}

func (x *SDataOut) GetHRList() [][]byte {
	if x != nil {
		return x.HRList
	}
	return nil
}

func (x *SDataOut) GetGammaList() [][]byte {
	if x != nil {
		return x.GammaList
	}
	return nil
}

type SignData struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Ssid []byte `protobuf:"bytes,1,opt,name=ssid,proto3" json:"ssid,omitempty"`
	R    []byte `protobuf:"bytes,2,opt,name=r,proto3" json:"r,omitempty"`
}

func (x *SignData) Reset() {
	*x = SignData{}
	if protoimpl.UnsafeEnabled {
		mi := &file_binance_tsslib_v2_protob_aleo_signing_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignData) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignData) ProtoMessage() {}

func (x *SignData) ProtoReflect() protoreflect.Message {
	mi := &file_binance_tsslib_v2_protob_aleo_signing_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignData.ProtoReflect.Descriptor instead.
func (*SignData) Descriptor() ([]byte, []int) {
	return file_binance_tsslib_v2_protob_aleo_signing_proto_rawDescGZIP(), []int{6}
}

func (x *SignData) GetSsid() []byte {
	if x != nil {
		return x.Ssid
	}
	return nil
}

func (x *SignData) GetR() []byte {
	if x != nil {
		return x.R
	}
	return nil
}

var File_binance_tsslib_v2_protob_aleo_signing_proto protoreflect.FileDescriptor

var file_binance_tsslib_v2_protob_aleo_signing_proto_rawDesc = []byte{
	0x0a, 0x2b, 0x62, 0x69, 0x6e, 0x61, 0x6e, 0x63, 0x65, 0x2f, 0x74, 0x73, 0x73, 0x6c, 0x69, 0x62,
	0x2f, 0x76, 0x32, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x2f, 0x61, 0x6c, 0x65, 0x6f, 0x2d,
	0x73, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x1e, 0x62,
	0x69, 0x6e, 0x61, 0x6e, 0x63, 0x65, 0x2e, 0x74, 0x73, 0x73, 0x6c, 0x69, 0x62, 0x2e, 0x76, 0x32,
	0x2e, 0x61, 0x6c, 0x65, 0x6f, 0x2e, 0x73, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x22, 0xbf, 0x01,
	0x0a, 0x11, 0x53, 0x69, 0x67, 0x6e, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x31, 0x4d, 0x65, 0x73, 0x73,
	0x61, 0x67, 0x65, 0x12, 0x1e, 0x0a, 0x0a, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e,
	0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0a, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d,
	0x65, 0x6e, 0x74, 0x12, 0x22, 0x0a, 0x0d, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x56, 0x5f, 0x73, 0x6b,
	0x5f, 0x73, 0x69, 0x67, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x0b, 0x70, 0x6f, 0x69, 0x6e,
	0x74, 0x56, 0x53, 0x6b, 0x53, 0x69, 0x67, 0x12, 0x22, 0x0a, 0x0d, 0x70, 0x72, 0x6f, 0x6f, 0x66,
	0x56, 0x5f, 0x73, 0x6b, 0x5f, 0x73, 0x69, 0x67, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x0b,
	0x70, 0x72, 0x6f, 0x6f, 0x66, 0x56, 0x53, 0x6b, 0x53, 0x69, 0x67, 0x12, 0x20, 0x0a, 0x0c, 0x70,
	0x6f, 0x69, 0x6e, 0x74, 0x56, 0x5f, 0x72, 0x5f, 0x73, 0x69, 0x67, 0x18, 0x04, 0x20, 0x03, 0x28,
	0x0c, 0x52, 0x0a, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x56, 0x52, 0x53, 0x69, 0x67, 0x12, 0x20, 0x0a,
	0x0c, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x56, 0x5f, 0x72, 0x5f, 0x73, 0x69, 0x67, 0x18, 0x05, 0x20,
	0x03, 0x28, 0x0c, 0x52, 0x0a, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x56, 0x52, 0x53, 0x69, 0x67, 0x22,
	0x7f, 0x0a, 0x11, 0x53, 0x69, 0x67, 0x6e, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x32, 0x4d, 0x65, 0x73,
	0x73, 0x61, 0x67, 0x65, 0x12, 0x23, 0x0a, 0x0d, 0x64, 0x65, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x69,
	0x74, 0x6d, 0x65, 0x6e, 0x74, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x0c, 0x64, 0x65, 0x43,
	0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x12, 0x16, 0x0a, 0x06, 0x70, 0x72, 0x6f,
	0x6f, 0x66, 0x44, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x06, 0x70, 0x72, 0x6f, 0x6f, 0x66,
	0x44, 0x12, 0x16, 0x0a, 0x06, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x45, 0x18, 0x03, 0x20, 0x03, 0x28,
	0x0c, 0x52, 0x06, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x45, 0x12, 0x15, 0x0a, 0x06, 0x73, 0x6b, 0x5f,
	0x74, 0x61, 0x67, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x05, 0x73, 0x6b, 0x54, 0x61, 0x67,
	0x22, 0x51, 0x0a, 0x11, 0x53, 0x69, 0x67, 0x6e, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x33, 0x4d, 0x65,
	0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x1d, 0x0a, 0x0a, 0x73, 0x68, 0x61, 0x72, 0x65, 0x5f, 0x6c,
	0x69, 0x73, 0x74, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x09, 0x73, 0x68, 0x61, 0x72, 0x65,
	0x4c, 0x69, 0x73, 0x74, 0x12, 0x1d, 0x0a, 0x0a, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x5f, 0x6c, 0x69,
	0x73, 0x74, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x09, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x4c,
	0x69, 0x73, 0x74, 0x22, 0x3a, 0x0a, 0x11, 0x53, 0x69, 0x67, 0x6e, 0x52, 0x6f, 0x75, 0x6e, 0x64,
	0x34, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x25, 0x0a, 0x0e, 0x72, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x73, 0x65, 0x5f, 0x73, 0x68, 0x61, 0x72, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c,
	0x52, 0x0d, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x53, 0x68, 0x61, 0x72, 0x65, 0x22,
	0x93, 0x01, 0x0a, 0x0a, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x4f, 0x75, 0x74, 0x12, 0x1c,
	0x0a, 0x09, 0x63, 0x68, 0x61, 0x6c, 0x6c, 0x65, 0x6e, 0x67, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x09, 0x63, 0x68, 0x61, 0x6c, 0x6c, 0x65, 0x6e, 0x67, 0x65, 0x12, 0x1a, 0x0a, 0x08,
	0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x08,
	0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x15, 0x0a, 0x06, 0x73, 0x6b, 0x5f, 0x74,
	0x61, 0x67, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x05, 0x73, 0x6b, 0x54, 0x61, 0x67, 0x12,
	0x10, 0x0a, 0x03, 0x74, 0x76, 0x6b, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x03, 0x74, 0x76,
	0x6b, 0x12, 0x10, 0x0a, 0x03, 0x74, 0x63, 0x6d, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x03,
	0x74, 0x63, 0x6d, 0x12, 0x10, 0x0a, 0x03, 0x73, 0x63, 0x6d, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0c,
	0x52, 0x03, 0x73, 0x63, 0x6d, 0x22, 0x7d, 0x0a, 0x08, 0x53, 0x44, 0x61, 0x74, 0x61, 0x4f, 0x75,
	0x74, 0x12, 0x10, 0x0a, 0x03, 0x74, 0x76, 0x6b, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x03,
	0x74, 0x76, 0x6b, 0x12, 0x15, 0x0a, 0x06, 0x73, 0x6b, 0x5f, 0x74, 0x61, 0x67, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x0c, 0x52, 0x05, 0x73, 0x6b, 0x54, 0x61, 0x67, 0x12, 0x0f, 0x0a, 0x03, 0x67, 0x5f,
	0x72, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x02, 0x67, 0x52, 0x12, 0x18, 0x0a, 0x08, 0x68,
	0x5f, 0x72, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x18, 0x04, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x06, 0x68,
	0x52, 0x4c, 0x69, 0x73, 0x74, 0x12, 0x1d, 0x0a, 0x0a, 0x67, 0x61, 0x6d, 0x6d, 0x61, 0x5f, 0x6c,
	0x69, 0x73, 0x74, 0x18, 0x05, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x09, 0x67, 0x61, 0x6d, 0x6d, 0x61,
	0x4c, 0x69, 0x73, 0x74, 0x22, 0x2c, 0x0a, 0x08, 0x53, 0x69, 0x67, 0x6e, 0x44, 0x61, 0x74, 0x61,
	0x12, 0x12, 0x0a, 0x04, 0x73, 0x73, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x04,
	0x73, 0x73, 0x69, 0x64, 0x12, 0x0c, 0x0a, 0x01, 0x72, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52,
	0x01, 0x72, 0x42, 0x0e, 0x5a, 0x0c, 0x61, 0x6c, 0x65, 0x6f, 0x2f, 0x73, 0x69, 0x67, 0x6e, 0x69,
	0x6e, 0x67, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_binance_tsslib_v2_protob_aleo_signing_proto_rawDescOnce sync.Once
	file_binance_tsslib_v2_protob_aleo_signing_proto_rawDescData = file_binance_tsslib_v2_protob_aleo_signing_proto_rawDesc
)

func file_binance_tsslib_v2_protob_aleo_signing_proto_rawDescGZIP() []byte {
	file_binance_tsslib_v2_protob_aleo_signing_proto_rawDescOnce.Do(func() {
		file_binance_tsslib_v2_protob_aleo_signing_proto_rawDescData = protoimpl.X.CompressGZIP(file_binance_tsslib_v2_protob_aleo_signing_proto_rawDescData)
	})
	return file_binance_tsslib_v2_protob_aleo_signing_proto_rawDescData
}

var file_binance_tsslib_v2_protob_aleo_signing_proto_msgTypes = make([]protoimpl.MessageInfo, 7)
var file_binance_tsslib_v2_protob_aleo_signing_proto_goTypes = []interface{}{
	(*SignRound1Message)(nil), // 0: binance.tsslib.v2.aleo.signing.SignRound1Message
	(*SignRound2Message)(nil), // 1: binance.tsslib.v2.aleo.signing.SignRound2Message
	(*SignRound3Message)(nil), // 2: binance.tsslib.v2.aleo.signing.SignRound3Message
	(*SignRound4Message)(nil), // 3: binance.tsslib.v2.aleo.signing.SignRound4Message
	(*RequestOut)(nil),        // 4: binance.tsslib.v2.aleo.signing.RequestOut
	(*SDataOut)(nil),          // 5: binance.tsslib.v2.aleo.signing.SDataOut
	(*SignData)(nil),          // 6: binance.tsslib.v2.aleo.signing.SignData
}
var file_binance_tsslib_v2_protob_aleo_signing_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_binance_tsslib_v2_protob_aleo_signing_proto_init() }
func file_binance_tsslib_v2_protob_aleo_signing_proto_init() {
	if File_binance_tsslib_v2_protob_aleo_signing_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_binance_tsslib_v2_protob_aleo_signing_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
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
		file_binance_tsslib_v2_protob_aleo_signing_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
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
		file_binance_tsslib_v2_protob_aleo_signing_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
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
		file_binance_tsslib_v2_protob_aleo_signing_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignRound4Message); i {
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
		file_binance_tsslib_v2_protob_aleo_signing_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RequestOut); i {
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
		file_binance_tsslib_v2_protob_aleo_signing_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SDataOut); i {
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
		file_binance_tsslib_v2_protob_aleo_signing_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignData); i {
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
			RawDescriptor: file_binance_tsslib_v2_protob_aleo_signing_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   7,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_binance_tsslib_v2_protob_aleo_signing_proto_goTypes,
		DependencyIndexes: file_binance_tsslib_v2_protob_aleo_signing_proto_depIdxs,
		MessageInfos:      file_binance_tsslib_v2_protob_aleo_signing_proto_msgTypes,
	}.Build()
	File_binance_tsslib_v2_protob_aleo_signing_proto = out.File
	file_binance_tsslib_v2_protob_aleo_signing_proto_rawDesc = nil
	file_binance_tsslib_v2_protob_aleo_signing_proto_goTypes = nil
	file_binance_tsslib_v2_protob_aleo_signing_proto_depIdxs = nil
}
