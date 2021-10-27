package cid

import "fmt"

var errUnknownInfo error = fmt.Errorf("未知的info类型")

const (
	BlockType_root   = 0
	BlockType_leaf   = 1
	BlockType_middle = 2
	Crypt_Y          = 1
	Crypt_N          = 0
	Auth_Y           = 1
	Auth_N           = 0
)

const (
	blockInfoMaxValue = 11
)
