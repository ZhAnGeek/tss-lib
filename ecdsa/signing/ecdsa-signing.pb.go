// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.31.0
// 	protoc        v4.24.2
// source: protob/ecdsa-signing.proto

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

// Represents a BROADCAST message sent to all parties during Round 4 of the ECDSA TSS signing protocol.
type SignRound1Message struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	SigmaShare []byte `protobuf:"bytes,1,opt,name=SigmaShare,proto3" json:"SigmaShare,omitempty"`
	Rx         []byte `protobuf:"bytes,2,opt,name=Rx,proto3" json:"Rx,omitempty"`
	Ry         []byte `protobuf:"bytes,3,opt,name=Ry,proto3" json:"Ry,omitempty"`
}

func (x *SignRound1Message) Reset() {
	*x = SignRound1Message{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_ecdsa_signing_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignRound1Message) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignRound1Message) ProtoMessage() {}

func (x *SignRound1Message) ProtoReflect() protoreflect.Message {
	mi := &file_protob_ecdsa_signing_proto_msgTypes[0]
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
	return file_protob_ecdsa_signing_proto_rawDescGZIP(), []int{0}
}

func (x *SignRound1Message) GetSigmaShare() []byte {
	if x != nil {
		return x.SigmaShare
	}
	return nil
}

func (x *SignRound1Message) GetRx() []byte {
	if x != nil {
		return x.Rx
	}
	return nil
}

func (x *SignRound1Message) GetRy() []byte {
	if x != nil {
		return x.Ry
	}
	return nil
}

type IdentificationRound1Message struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	H        []byte   `protobuf:"bytes,1,opt,name=H,proto3" json:"H,omitempty"`
	MulProof [][]byte `protobuf:"bytes,2,rep,name=MulProof,proto3" json:"MulProof,omitempty"`
	Djis     [][]byte `protobuf:"bytes,3,rep,name=Djis,proto3" json:"Djis,omitempty"`
	Fjis     [][]byte `protobuf:"bytes,4,rep,name=Fjis,proto3" json:"Fjis,omitempty"`
	// repeated bytes DjiProofs = 5;
	DecProof [][]byte `protobuf:"bytes,6,rep,name=DecProof,proto3" json:"DecProof,omitempty"`
	Q3Enc    []byte   `protobuf:"bytes,7,opt,name=Q3Enc,proto3" json:"Q3Enc,omitempty"`
}

func (x *IdentificationRound1Message) Reset() {
	*x = IdentificationRound1Message{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_ecdsa_signing_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *IdentificationRound1Message) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*IdentificationRound1Message) ProtoMessage() {}

func (x *IdentificationRound1Message) ProtoReflect() protoreflect.Message {
	mi := &file_protob_ecdsa_signing_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use IdentificationRound1Message.ProtoReflect.Descriptor instead.
func (*IdentificationRound1Message) Descriptor() ([]byte, []int) {
	return file_protob_ecdsa_signing_proto_rawDescGZIP(), []int{1}
}

func (x *IdentificationRound1Message) GetH() []byte {
	if x != nil {
		return x.H
	}
	return nil
}

func (x *IdentificationRound1Message) GetMulProof() [][]byte {
	if x != nil {
		return x.MulProof
	}
	return nil
}

func (x *IdentificationRound1Message) GetDjis() [][]byte {
	if x != nil {
		return x.Djis
	}
	return nil
}

func (x *IdentificationRound1Message) GetFjis() [][]byte {
	if x != nil {
		return x.Fjis
	}
	return nil
}

func (x *IdentificationRound1Message) GetDecProof() [][]byte {
	if x != nil {
		return x.DecProof
	}
	return nil
}

func (x *IdentificationRound1Message) GetQ3Enc() []byte {
	if x != nil {
		return x.Q3Enc
	}
	return nil
}

// Container for LocalDump
type LocalDumpPB struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Index                int32    `protobuf:"varint,1,opt,name=Index,proto3" json:"Index,omitempty"`
	RoundNum             int32    `protobuf:"varint,2,opt,name=RoundNum,proto3" json:"RoundNum,omitempty"`
	LTw                  []byte   `protobuf:"bytes,4,opt,name=LTw,proto3" json:"LTw,omitempty"`
	LTBigWs              [][]byte `protobuf:"bytes,5,rep,name=LTBigWs,proto3" json:"LTBigWs,omitempty"`
	LTm                  []byte   `protobuf:"bytes,6,opt,name=LTm,proto3" json:"LTm,omitempty"`
	LTKeyDerivationDelta []byte   `protobuf:"bytes,7,opt,name=LTKeyDerivationDelta,proto3" json:"LTKeyDerivationDelta,omitempty"`
	LTssid               []byte   `protobuf:"bytes,8,opt,name=LTssid,proto3" json:"LTssid,omitempty"`
	LTKShare             []byte   `protobuf:"bytes,9,opt,name=LTKShare,proto3" json:"LTKShare,omitempty"`
	LTChiShare           []byte   `protobuf:"bytes,10,opt,name=LTChiShare,proto3" json:"LTChiShare,omitempty"`
	LTBigR               [][]byte `protobuf:"bytes,11,rep,name=LTBigR,proto3" json:"LTBigR,omitempty"`
	LTSigmaShare         []byte   `protobuf:"bytes,12,opt,name=LTSigmaShare,proto3" json:"LTSigmaShare,omitempty"`
	// identification
	LTK                 []byte   `protobuf:"bytes,13,opt,name=LTK,proto3" json:"LTK,omitempty"`
	LTr1MsgK            [][]byte `protobuf:"bytes,14,rep,name=LTr1msgK,proto3" json:"LTr1msgK,omitempty"`
	LTChiShareAlphas    [][]byte `protobuf:"bytes,15,rep,name=LTChiShareAlphas,proto3" json:"LTChiShareAlphas,omitempty"`
	LTChiShareBetas     [][]byte `protobuf:"bytes,16,rep,name=LTChiShareBetas,proto3" json:"LTChiShareBetas,omitempty"`
	LTr2MsgChiD         [][]byte `protobuf:"bytes,17,rep,name=LTr2msgChiD,proto3" json:"LTr2msgChiD,omitempty"`
	LTChiMtAFs          [][]byte `protobuf:"bytes,18,rep,name=LTChiMtAFs,proto3" json:"LTChiMtAFs,omitempty"`
	LTChiMtADs          [][]byte `protobuf:"bytes,19,rep,name=LTChiMtADs,proto3" json:"LTChiMtADs,omitempty"`
	LTChiMtADProofs     [][]byte `protobuf:"bytes,20,rep,name=LTChiMtADProofs,proto3" json:"LTChiMtADProofs,omitempty"`
	LTr4MsgSigmaShare   [][]byte `protobuf:"bytes,21,rep,name=LTr4msgSigmaShare,proto3" json:"LTr4msgSigmaShare,omitempty"`
	LTr5MsgH            [][]byte `protobuf:"bytes,22,rep,name=LTr5msgH,proto3" json:"LTr5msgH,omitempty"`
	LTr5MsgProofMulstar [][]byte `protobuf:"bytes,23,rep,name=LTr5msgProofMulstar,proto3" json:"LTr5msgProofMulstar,omitempty"`
	LTr5MsgProofDec     [][]byte `protobuf:"bytes,25,rep,name=LTr5msgProofDec,proto3" json:"LTr5msgProofDec,omitempty"`
	LTr5MsgDjis         [][]byte `protobuf:"bytes,26,rep,name=LTr5msgDjis,proto3" json:"LTr5msgDjis,omitempty"`
	LTr5MsgFjis         [][]byte `protobuf:"bytes,27,rep,name=LTr5msgFjis,proto3" json:"LTr5msgFjis,omitempty"`
	LTssidNonce         []byte   `protobuf:"bytes,28,opt,name=LTssidNonce,proto3" json:"LTssidNonce,omitempty"`
}

func (x *LocalDumpPB) Reset() {
	*x = LocalDumpPB{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_ecdsa_signing_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *LocalDumpPB) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LocalDumpPB) ProtoMessage() {}

func (x *LocalDumpPB) ProtoReflect() protoreflect.Message {
	mi := &file_protob_ecdsa_signing_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LocalDumpPB.ProtoReflect.Descriptor instead.
func (*LocalDumpPB) Descriptor() ([]byte, []int) {
	return file_protob_ecdsa_signing_proto_rawDescGZIP(), []int{2}
}

func (x *LocalDumpPB) GetIndex() int32 {
	if x != nil {
		return x.Index
	}
	return 0
}

func (x *LocalDumpPB) GetRoundNum() int32 {
	if x != nil {
		return x.RoundNum
	}
	return 0
}

func (x *LocalDumpPB) GetLTw() []byte {
	if x != nil {
		return x.LTw
	}
	return nil
}

func (x *LocalDumpPB) GetLTBigWs() [][]byte {
	if x != nil {
		return x.LTBigWs
	}
	return nil
}

func (x *LocalDumpPB) GetLTm() []byte {
	if x != nil {
		return x.LTm
	}
	return nil
}

func (x *LocalDumpPB) GetLTKeyDerivationDelta() []byte {
	if x != nil {
		return x.LTKeyDerivationDelta
	}
	return nil
}

func (x *LocalDumpPB) GetLTssid() []byte {
	if x != nil {
		return x.LTssid
	}
	return nil
}

func (x *LocalDumpPB) GetLTKShare() []byte {
	if x != nil {
		return x.LTKShare
	}
	return nil
}

func (x *LocalDumpPB) GetLTChiShare() []byte {
	if x != nil {
		return x.LTChiShare
	}
	return nil
}

func (x *LocalDumpPB) GetLTBigR() [][]byte {
	if x != nil {
		return x.LTBigR
	}
	return nil
}

func (x *LocalDumpPB) GetLTSigmaShare() []byte {
	if x != nil {
		return x.LTSigmaShare
	}
	return nil
}

func (x *LocalDumpPB) GetLTK() []byte {
	if x != nil {
		return x.LTK
	}
	return nil
}

func (x *LocalDumpPB) GetLTr1MsgK() [][]byte {
	if x != nil {
		return x.LTr1MsgK
	}
	return nil
}

func (x *LocalDumpPB) GetLTChiShareAlphas() [][]byte {
	if x != nil {
		return x.LTChiShareAlphas
	}
	return nil
}

func (x *LocalDumpPB) GetLTChiShareBetas() [][]byte {
	if x != nil {
		return x.LTChiShareBetas
	}
	return nil
}

func (x *LocalDumpPB) GetLTr2MsgChiD() [][]byte {
	if x != nil {
		return x.LTr2MsgChiD
	}
	return nil
}

func (x *LocalDumpPB) GetLTChiMtAFs() [][]byte {
	if x != nil {
		return x.LTChiMtAFs
	}
	return nil
}

func (x *LocalDumpPB) GetLTChiMtADs() [][]byte {
	if x != nil {
		return x.LTChiMtADs
	}
	return nil
}

func (x *LocalDumpPB) GetLTChiMtADProofs() [][]byte {
	if x != nil {
		return x.LTChiMtADProofs
	}
	return nil
}

func (x *LocalDumpPB) GetLTr4MsgSigmaShare() [][]byte {
	if x != nil {
		return x.LTr4MsgSigmaShare
	}
	return nil
}

func (x *LocalDumpPB) GetLTr5MsgH() [][]byte {
	if x != nil {
		return x.LTr5MsgH
	}
	return nil
}

func (x *LocalDumpPB) GetLTr5MsgProofMulstar() [][]byte {
	if x != nil {
		return x.LTr5MsgProofMulstar
	}
	return nil
}

func (x *LocalDumpPB) GetLTr5MsgProofDec() [][]byte {
	if x != nil {
		return x.LTr5MsgProofDec
	}
	return nil
}

func (x *LocalDumpPB) GetLTr5MsgDjis() [][]byte {
	if x != nil {
		return x.LTr5MsgDjis
	}
	return nil
}

func (x *LocalDumpPB) GetLTr5MsgFjis() [][]byte {
	if x != nil {
		return x.LTr5MsgFjis
	}
	return nil
}

func (x *LocalDumpPB) GetLTssidNonce() []byte {
	if x != nil {
		return x.LTssidNonce
	}
	return nil
}

var File_protob_ecdsa_signing_proto protoreflect.FileDescriptor

var file_protob_ecdsa_signing_proto_rawDesc = []byte{
	0x0a, 0x1a, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x2f, 0x65, 0x63, 0x64, 0x73, 0x61, 0x2d, 0x73,
	0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x1c, 0x62, 0x69,
	0x6e, 0x61, 0x6e, 0x63, 0x65, 0x2e, 0x74, 0x73, 0x73, 0x6c, 0x69, 0x62, 0x2e, 0x65, 0x63, 0x64,
	0x73, 0x61, 0x2e, 0x73, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x22, 0x53, 0x0a, 0x11, 0x53, 0x69,
	0x67, 0x6e, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x31, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12,
	0x1e, 0x0a, 0x0a, 0x53, 0x69, 0x67, 0x6d, 0x61, 0x53, 0x68, 0x61, 0x72, 0x65, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0c, 0x52, 0x0a, 0x53, 0x69, 0x67, 0x6d, 0x61, 0x53, 0x68, 0x61, 0x72, 0x65, 0x12,
	0x0e, 0x0a, 0x02, 0x52, 0x78, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x02, 0x52, 0x78, 0x12,
	0x0e, 0x0a, 0x02, 0x52, 0x79, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x02, 0x52, 0x79, 0x22,
	0xa1, 0x01, 0x0a, 0x1b, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x31, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12,
	0x0c, 0x0a, 0x01, 0x48, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x01, 0x48, 0x12, 0x1a, 0x0a,
	0x08, 0x4d, 0x75, 0x6c, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0c, 0x52,
	0x08, 0x4d, 0x75, 0x6c, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x12, 0x12, 0x0a, 0x04, 0x44, 0x6a, 0x69,
	0x73, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x04, 0x44, 0x6a, 0x69, 0x73, 0x12, 0x12, 0x0a,
	0x04, 0x46, 0x6a, 0x69, 0x73, 0x18, 0x04, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x04, 0x46, 0x6a, 0x69,
	0x73, 0x12, 0x1a, 0x0a, 0x08, 0x44, 0x65, 0x63, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x18, 0x06, 0x20,
	0x03, 0x28, 0x0c, 0x52, 0x08, 0x44, 0x65, 0x63, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x12, 0x14, 0x0a,
	0x05, 0x51, 0x33, 0x45, 0x6e, 0x63, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x05, 0x51, 0x33,
	0x45, 0x6e, 0x63, 0x22, 0xdd, 0x06, 0x0a, 0x0b, 0x4c, 0x6f, 0x63, 0x61, 0x6c, 0x44, 0x75, 0x6d,
	0x70, 0x50, 0x42, 0x12, 0x14, 0x0a, 0x05, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x05, 0x52, 0x05, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x12, 0x1a, 0x0a, 0x08, 0x52, 0x6f, 0x75,
	0x6e, 0x64, 0x4e, 0x75, 0x6d, 0x18, 0x02, 0x20, 0x01, 0x28, 0x05, 0x52, 0x08, 0x52, 0x6f, 0x75,
	0x6e, 0x64, 0x4e, 0x75, 0x6d, 0x12, 0x10, 0x0a, 0x03, 0x4c, 0x54, 0x77, 0x18, 0x04, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x03, 0x4c, 0x54, 0x77, 0x12, 0x18, 0x0a, 0x07, 0x4c, 0x54, 0x42, 0x69, 0x67,
	0x57, 0x73, 0x18, 0x05, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x07, 0x4c, 0x54, 0x42, 0x69, 0x67, 0x57,
	0x73, 0x12, 0x10, 0x0a, 0x03, 0x4c, 0x54, 0x6d, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x03,
	0x4c, 0x54, 0x6d, 0x12, 0x32, 0x0a, 0x14, 0x4c, 0x54, 0x4b, 0x65, 0x79, 0x44, 0x65, 0x72, 0x69,
	0x76, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x44, 0x65, 0x6c, 0x74, 0x61, 0x18, 0x07, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x14, 0x4c, 0x54, 0x4b, 0x65, 0x79, 0x44, 0x65, 0x72, 0x69, 0x76, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x44, 0x65, 0x6c, 0x74, 0x61, 0x12, 0x16, 0x0a, 0x06, 0x4c, 0x54, 0x73, 0x73, 0x69,
	0x64, 0x18, 0x08, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x06, 0x4c, 0x54, 0x73, 0x73, 0x69, 0x64, 0x12,
	0x1a, 0x0a, 0x08, 0x4c, 0x54, 0x4b, 0x53, 0x68, 0x61, 0x72, 0x65, 0x18, 0x09, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x08, 0x4c, 0x54, 0x4b, 0x53, 0x68, 0x61, 0x72, 0x65, 0x12, 0x1e, 0x0a, 0x0a, 0x4c,
	0x54, 0x43, 0x68, 0x69, 0x53, 0x68, 0x61, 0x72, 0x65, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x0c, 0x52,
	0x0a, 0x4c, 0x54, 0x43, 0x68, 0x69, 0x53, 0x68, 0x61, 0x72, 0x65, 0x12, 0x16, 0x0a, 0x06, 0x4c,
	0x54, 0x42, 0x69, 0x67, 0x52, 0x18, 0x0b, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x06, 0x4c, 0x54, 0x42,
	0x69, 0x67, 0x52, 0x12, 0x22, 0x0a, 0x0c, 0x4c, 0x54, 0x53, 0x69, 0x67, 0x6d, 0x61, 0x53, 0x68,
	0x61, 0x72, 0x65, 0x18, 0x0c, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0c, 0x4c, 0x54, 0x53, 0x69, 0x67,
	0x6d, 0x61, 0x53, 0x68, 0x61, 0x72, 0x65, 0x12, 0x10, 0x0a, 0x03, 0x4c, 0x54, 0x4b, 0x18, 0x0d,
	0x20, 0x01, 0x28, 0x0c, 0x52, 0x03, 0x4c, 0x54, 0x4b, 0x12, 0x1a, 0x0a, 0x08, 0x4c, 0x54, 0x72,
	0x31, 0x6d, 0x73, 0x67, 0x4b, 0x18, 0x0e, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x08, 0x4c, 0x54, 0x72,
	0x31, 0x6d, 0x73, 0x67, 0x4b, 0x12, 0x2a, 0x0a, 0x10, 0x4c, 0x54, 0x43, 0x68, 0x69, 0x53, 0x68,
	0x61, 0x72, 0x65, 0x41, 0x6c, 0x70, 0x68, 0x61, 0x73, 0x18, 0x0f, 0x20, 0x03, 0x28, 0x0c, 0x52,
	0x10, 0x4c, 0x54, 0x43, 0x68, 0x69, 0x53, 0x68, 0x61, 0x72, 0x65, 0x41, 0x6c, 0x70, 0x68, 0x61,
	0x73, 0x12, 0x28, 0x0a, 0x0f, 0x4c, 0x54, 0x43, 0x68, 0x69, 0x53, 0x68, 0x61, 0x72, 0x65, 0x42,
	0x65, 0x74, 0x61, 0x73, 0x18, 0x10, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x0f, 0x4c, 0x54, 0x43, 0x68,
	0x69, 0x53, 0x68, 0x61, 0x72, 0x65, 0x42, 0x65, 0x74, 0x61, 0x73, 0x12, 0x20, 0x0a, 0x0b, 0x4c,
	0x54, 0x72, 0x32, 0x6d, 0x73, 0x67, 0x43, 0x68, 0x69, 0x44, 0x18, 0x11, 0x20, 0x03, 0x28, 0x0c,
	0x52, 0x0b, 0x4c, 0x54, 0x72, 0x32, 0x6d, 0x73, 0x67, 0x43, 0x68, 0x69, 0x44, 0x12, 0x1e, 0x0a,
	0x0a, 0x4c, 0x54, 0x43, 0x68, 0x69, 0x4d, 0x74, 0x41, 0x46, 0x73, 0x18, 0x12, 0x20, 0x03, 0x28,
	0x0c, 0x52, 0x0a, 0x4c, 0x54, 0x43, 0x68, 0x69, 0x4d, 0x74, 0x41, 0x46, 0x73, 0x12, 0x1e, 0x0a,
	0x0a, 0x4c, 0x54, 0x43, 0x68, 0x69, 0x4d, 0x74, 0x41, 0x44, 0x73, 0x18, 0x13, 0x20, 0x03, 0x28,
	0x0c, 0x52, 0x0a, 0x4c, 0x54, 0x43, 0x68, 0x69, 0x4d, 0x74, 0x41, 0x44, 0x73, 0x12, 0x28, 0x0a,
	0x0f, 0x4c, 0x54, 0x43, 0x68, 0x69, 0x4d, 0x74, 0x41, 0x44, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x73,
	0x18, 0x14, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x0f, 0x4c, 0x54, 0x43, 0x68, 0x69, 0x4d, 0x74, 0x41,
	0x44, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x73, 0x12, 0x2c, 0x0a, 0x11, 0x4c, 0x54, 0x72, 0x34, 0x6d,
	0x73, 0x67, 0x53, 0x69, 0x67, 0x6d, 0x61, 0x53, 0x68, 0x61, 0x72, 0x65, 0x18, 0x15, 0x20, 0x03,
	0x28, 0x0c, 0x52, 0x11, 0x4c, 0x54, 0x72, 0x34, 0x6d, 0x73, 0x67, 0x53, 0x69, 0x67, 0x6d, 0x61,
	0x53, 0x68, 0x61, 0x72, 0x65, 0x12, 0x1a, 0x0a, 0x08, 0x4c, 0x54, 0x72, 0x35, 0x6d, 0x73, 0x67,
	0x48, 0x18, 0x16, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x08, 0x4c, 0x54, 0x72, 0x35, 0x6d, 0x73, 0x67,
	0x48, 0x12, 0x30, 0x0a, 0x13, 0x4c, 0x54, 0x72, 0x35, 0x6d, 0x73, 0x67, 0x50, 0x72, 0x6f, 0x6f,
	0x66, 0x4d, 0x75, 0x6c, 0x73, 0x74, 0x61, 0x72, 0x18, 0x17, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x13,
	0x4c, 0x54, 0x72, 0x35, 0x6d, 0x73, 0x67, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x4d, 0x75, 0x6c, 0x73,
	0x74, 0x61, 0x72, 0x12, 0x28, 0x0a, 0x0f, 0x4c, 0x54, 0x72, 0x35, 0x6d, 0x73, 0x67, 0x50, 0x72,
	0x6f, 0x6f, 0x66, 0x44, 0x65, 0x63, 0x18, 0x19, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x0f, 0x4c, 0x54,
	0x72, 0x35, 0x6d, 0x73, 0x67, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x44, 0x65, 0x63, 0x12, 0x20, 0x0a,
	0x0b, 0x4c, 0x54, 0x72, 0x35, 0x6d, 0x73, 0x67, 0x44, 0x6a, 0x69, 0x73, 0x18, 0x1a, 0x20, 0x03,
	0x28, 0x0c, 0x52, 0x0b, 0x4c, 0x54, 0x72, 0x35, 0x6d, 0x73, 0x67, 0x44, 0x6a, 0x69, 0x73, 0x12,
	0x20, 0x0a, 0x0b, 0x4c, 0x54, 0x72, 0x35, 0x6d, 0x73, 0x67, 0x46, 0x6a, 0x69, 0x73, 0x18, 0x1b,
	0x20, 0x03, 0x28, 0x0c, 0x52, 0x0b, 0x4c, 0x54, 0x72, 0x35, 0x6d, 0x73, 0x67, 0x46, 0x6a, 0x69,
	0x73, 0x12, 0x20, 0x0a, 0x0b, 0x4c, 0x54, 0x73, 0x73, 0x69, 0x64, 0x4e, 0x6f, 0x6e, 0x63, 0x65,
	0x18, 0x1c, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0b, 0x4c, 0x54, 0x73, 0x73, 0x69, 0x64, 0x4e, 0x6f,
	0x6e, 0x63, 0x65, 0x42, 0x0f, 0x5a, 0x0d, 0x65, 0x63, 0x64, 0x73, 0x61, 0x2f, 0x73, 0x69, 0x67,
	0x6e, 0x69, 0x6e, 0x67, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_protob_ecdsa_signing_proto_rawDescOnce sync.Once
	file_protob_ecdsa_signing_proto_rawDescData = file_protob_ecdsa_signing_proto_rawDesc
)

func file_protob_ecdsa_signing_proto_rawDescGZIP() []byte {
	file_protob_ecdsa_signing_proto_rawDescOnce.Do(func() {
		file_protob_ecdsa_signing_proto_rawDescData = protoimpl.X.CompressGZIP(file_protob_ecdsa_signing_proto_rawDescData)
	})
	return file_protob_ecdsa_signing_proto_rawDescData
}

var file_protob_ecdsa_signing_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_protob_ecdsa_signing_proto_goTypes = []interface{}{
	(*SignRound1Message)(nil),           // 0: binance.tsslib.ecdsa.signing.SignRound1Message
	(*IdentificationRound1Message)(nil), // 1: binance.tsslib.ecdsa.signing.IdentificationRound1Message
	(*LocalDumpPB)(nil),                 // 2: binance.tsslib.ecdsa.signing.LocalDumpPB
}
var file_protob_ecdsa_signing_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_protob_ecdsa_signing_proto_init() }
func file_protob_ecdsa_signing_proto_init() {
	if File_protob_ecdsa_signing_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_protob_ecdsa_signing_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
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
		file_protob_ecdsa_signing_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*IdentificationRound1Message); i {
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
		file_protob_ecdsa_signing_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*LocalDumpPB); i {
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
			RawDescriptor: file_protob_ecdsa_signing_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_protob_ecdsa_signing_proto_goTypes,
		DependencyIndexes: file_protob_ecdsa_signing_proto_depIdxs,
		MessageInfos:      file_protob_ecdsa_signing_proto_msgTypes,
	}.Build()
	File_protob_ecdsa_signing_proto = out.File
	file_protob_ecdsa_signing_proto_rawDesc = nil
	file_protob_ecdsa_signing_proto_goTypes = nil
	file_protob_ecdsa_signing_proto_depIdxs = nil
}
