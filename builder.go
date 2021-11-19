package cid

import (
	mh "github.com/multiformats/go-multihash"
)

type Builder interface {
	Sum(data []byte) (Cid, error)
	GetCodec() uint64
	WithCodec(uint64) Builder
	SetBlockInfo(blockInfo uint64) Builder
	GetBlockInfo() uint64
}

type V0Builder struct{}

type V1Builder struct {
	Codec    uint64
	MhType   uint64
	MhLength int // MhLength <= 0 means the default length
}

type V2Builder struct {
	BlockInfo uint64
	Codec     uint64
	MhType    uint64
	MhLength  int // MhLength <= 0 means the default length
}

func (p Prefix) GetCodec() uint64 {
	return p.Codec
}

func (p Prefix) WithCodec(c uint64) Builder {
	if c == p.Codec {
		return p
	}
	p.Codec = c
	if c != DagProtobuf {
		p.Version = 1
	}
	return p
}

func (p Prefix) SetBlockInfo(c uint64) Builder {
	p.BlockInfo = c
	return p
}

func (p Prefix) GetBlockInfo() uint64 {
	return p.BlockInfo
}

func (p V0Builder) Sum(data []byte) (Cid, error) {
	hash, err := mh.Sum(data, mh.SHA2_256, -1)
	if err != nil {
		return Undef, err
	}
	return Cid{string(hash)}, nil
}

func (p V0Builder) GetCodec() uint64 {
	return DagProtobuf
}

func (p V0Builder) WithCodec(c uint64) Builder {
	if c == DagProtobuf {
		return p
	}
	return V1Builder{Codec: c, MhType: mh.SHA2_256}
}

func (p V0Builder) SetBlockInfo(c uint64) Builder {
	return p
}

func (p V0Builder) GetBlockInfo() uint64 {
	return 0
}

func (p V1Builder) Sum(data []byte) (Cid, error) {
	mhLen := p.MhLength
	if mhLen <= 0 {
		mhLen = -1
	}
	hash, err := mh.Sum(data, p.MhType, mhLen)
	if err != nil {
		return Undef, err
	}
	return NewCidV1(p.Codec, hash), nil
}

func (p V1Builder) GetCodec() uint64 {
	return p.Codec
}

func (p V1Builder) WithCodec(c uint64) Builder {
	p.Codec = c
	return p
}
func (p V1Builder) SetBlockInfo(c uint64) Builder {
	return p
}

func (p V1Builder) GetBlockInfo() uint64 {
	return 0
}

func (p V2Builder) Sum(data []byte) (Cid, error) {
	mhLen := p.MhLength
	if mhLen <= 0 {
		mhLen = -1
	}
	hash, err := mh.Sum(data, p.MhType, mhLen)
	if err != nil {
		return Undef, err
	}
	return NewCidV2(p.BlockInfo, p.Codec, hash), nil
}

func (p V2Builder) GetCodec() uint64 {
	return p.Codec
}

func (p V2Builder) WithCodec(c uint64) Builder {
	p.Codec = c
	return p
}

func (p V2Builder) SetBlockInfo(c uint64) Builder {
	p.BlockInfo = c
	return p
}

func (p V2Builder) GetBlockInfo() uint64 {
	return p.BlockInfo
}
