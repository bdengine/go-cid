package cid

import "fmt"

var errUnknownInfo error = fmt.Errorf("未知的info类型")

const (
	Tar_Y            = 1
	Tar_N            = 0
	BlockType_root   = 1
	BlockType_leaf   = 0
	BlockType_crypt  = 3
	BlockType_middle = 2
	Crypt_Y          = 1
	Crypt_N          = 0
	Auth_Y           = 1
	Auth_N           = 0
)

const (
	blockInfoMaxValue = 31
	maxValue          = 31
)

type InfoMask uint64

const (
	Tar       InfoMask = 1 << 4
	BlockType InfoMask = 3 << 2
	Crypt     InfoMask = 1 << 1
	Auth      InfoMask = 1 << 0
)

var m map[InfoMask]int = map[InfoMask]int{Tar: 4, BlockType: 2, Crypt: 1, Auth: 0}
var vMap map[InfoMask]int = map[InfoMask]int{BlockType: 1}
