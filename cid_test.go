package cid

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/multiformats/go-base32"
	"io/ioutil"
	"math/rand"
	"strings"
	"testing"
	"time"

	mbase "github.com/multiformats/go-multibase"
	mh "github.com/multiformats/go-multihash"
)

type Solution struct {
	nums, origin []int
}

func Constructor(nums []int) Solution {
	return Solution{
		nums:   nums,
		origin: append([]int{}, nums...),
	}
}

func (this *Solution) Reset() []int {
	copy(this.nums, this.origin)
	return this.nums
}

func (this *Solution) Shuffle() []int {
	l := len(this.origin)
	for i := 0; i < l; i++ {
		j := rand.Intn(l-i) + i
		this.nums[i], this.nums[j] = this.nums[j], this.nums[i]
	}
	return this.nums
}

// 测试cid转为文件路径
func TestCidToKey(t *testing.T) {
	cid, err := Decode("QmNcJh4CktxMhJE7VcQ1VvCTbKHRA9rw5uoGcBWRZ2zQKC")
	if err != nil {
		t.Fatal(err.Error())
	}
	rawKey := cid.Bytes()
	buf := make([]byte, 1+base32.RawStdEncoding.EncodedLen(len(rawKey)))
	buf[0] = '/'
	base32.RawStdEncoding.Encode(buf[1:], rawKey)
	s := string(buf)
	length := len(s)
	fmt.Println(s[length-3:length-1] + s)
}

func TestBlockInfo(t *testing.T) {
	for i := 0; i <= blockInfoMaxValue; i++ {
		// 测试解析
		tar, blockType, crypt, auth, err := ParseBlocInfo(uint64(i))
		if err != nil {
			t.Fatalf("blockInfo:%v 解析错误:%v", i, err)
		}
		// 测试生成
		info := GetBlockInfo(tar, blockType, crypt, auth)
		if info != uint64(i) {
			t.Fatalf("blockInfo 生成错误:%v", err)
		}

		// 测试mask读取
		t1, err := ParseBlocInfoMask(info, Tar)
		b1, err := ParseBlocInfoMask(info, BlockType)
		c1, err := ParseBlocInfoMask(info, Crypt)
		a1, err := ParseBlocInfoMask(info, Auth)
		if tar != t1 || blockType != b1 || crypt != c1 || auth != a1 {
			fmt.Println(tar, blockType, crypt, auth)
			fmt.Println(t1, b1, c1, a1)
			t.Fatal("mask 读取错误")
		}

		// 测试maskChange
		masks := []InfoMask{Tar, BlockType, Crypt, Auth}
		for _, mask := range masks {
			for j := 0; j <= vMap[mask]+1; j++ {
				tempInfo, err := TurnInfoMask(info, mask, uint8(j))
				v, err := ParseBlocInfoMask(tempInfo, mask)
				if err != nil {
					t.Fatal(err)
				}
				if int(v) != j {
					fmt.Println(mask, j, v)
					t.Fatal("ParseBlocInfoMask()返回值出错")
				}
			}
		}
	}
}

// 测试cid版本
func TestCidVersion(t *testing.T) {
	cidStr := "bafkreidilpdrqhbixsivli7t7xvoiyh7eh36puqx7kwvkh6quouiiye6ee"
	cidv0, err := Decode(cidStr)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(cidv0.Version())
	//cidv1 := NewCidV1(DagProtobuf, cidv0.Hash())
	blockInfo := GetBlockInfo(Tar_N, BlockType_root, Crypt_N, Auth_Y)
	cidV2 := NewCidV2(blockInfo, DagProtobuf, cidv0.Hash())
	cidv0.Hash()
	/*if cidv0.Version() != 2 || cidv1.Version() != 1 || cidV2.Version() != 2 {
		t.Fatal("version2 version is wrong")
	}*/
	prefix := cidV2.Prefix()
	p0 := cidv0.Prefix()
	fmt.Println(p0)
	tar, blockType, crypt, auth, err := ParseBlocInfo(p0.BlockInfo)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("压缩：%v,类型:%v,加密:%v,鉴权:%v\n", tar, blockType, crypt, auth)
	if prefix.BlockInfo != blockInfo || prefix.Version != 2 || prefix.Codec != DagProtobuf {
		t.Fatal("version2 prefix is wrong")
	}
	fmt.Println(cidV2.String())

}

func TestCidV2Sum(t *testing.T) {
	b, err := ioutil.ReadFile("D:/IPFSSTORAGE/blocks/ZZ/CIQA6NGR6UWAWAA5KDXAPATKDBLCNFBN6PQBRWBE4NZKMLFNRDIZZZQ.data")
	if err != nil {
		t.Fatal(err)
	}
	v0Builder := V0Builder{}
	v1Builder := V1Builder{
		Codec:    DagProtobuf,
		MhType:   mh.SHA2_256,
		MhLength: 0,
	}
	v2Builder := V2Builder{
		BlockInfo: 0,
		Codec:     DagProtobuf,
		MhType:    mh.SHA2_256,
		MhLength:  0,
	}
	v2Builder2 := V2Builder{
		BlockInfo: 1,
		Codec:     DagProtobuf,
		MhType:    mh.SHA2_256,
		MhLength:  0,
	}
	cidv0, err := v0Builder.Sum(b)
	if err != nil {
		t.Fatal(err)
	}
	cidv1, err := v1Builder.Sum(b)
	if err != nil {
		t.Fatal(err)
	}
	cidv2, err := v2Builder.Sum(b)
	if err != nil {
		t.Fatal(err)
	}
	cidv22, err := v2Builder2.Sum(b)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(cidv0)
	fmt.Println(cidv1)
	fmt.Println(cidv2)
	fmt.Println(cidv22)
	if cidv0.Hash().B58String() != cidv1.Hash().B58String() || cidv1.Hash().B58String() != cidv2.Hash().B58String() ||
		cidv2.Hash().B58String() != cidv22.Hash().B58String() {
		t.Fatal("hash 不相等")
	}
}

func TestNewCidV2(t *testing.T) {
	cidStr := "QmaoijWRDi2tcqVLnksTE5R7WqfggNsHLZHYk1bzSybexe"
	cidv0, err := Decode(cidStr)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(NewCidV1(DagProtobuf, cidv0.Hash()))
	for i := 0; i < 13; i++ {
		cidV2 := NewCidV2(uint64(i), DagProtobuf, cidv0.Hash()).String()
		fmt.Println(cidV2)
	}
}

func TestNewCidInfo(t *testing.T) {
	cidStr := "baikxaerarjn624dgwyc7f3yd4bmwmuuubrbklyxxah6gpuzqhh2e67aqimmq"
	cid, err := Decode(cidStr)
	if err != nil {
		t.Fatal(err)
	}
	tar, bType, crypt, auth, err := ParseBlocInfo(cid.Prefix().BlockInfo)

	fmt.Println(tar, bType, crypt, auth)

}

// Copying the "silly test" idea from
// https://github.com/multiformats/go-multihash/blob/7aa9f26a231c6f34f4e9fad52bf580fd36627285/multihash_test.go#L13
// Makes it so changing the table accidentally has to happen twice.
var tCodecs = map[uint64]string{
	Raw:                   "raw",
	DagProtobuf:           "protobuf",
	DagCBOR:               "cbor",
	Libp2pKey:             "libp2p-key",
	GitRaw:                "git-raw",
	EthBlock:              "eth-block",
	EthBlockList:          "eth-block-list",
	EthTxTrie:             "eth-tx-trie",
	EthTx:                 "eth-tx",
	EthTxReceiptTrie:      "eth-tx-receipt-trie",
	EthTxReceipt:          "eth-tx-receipt",
	EthStateTrie:          "eth-state-trie",
	EthAccountSnapshot:    "eth-account-snapshot",
	EthStorageTrie:        "eth-storage-trie",
	BitcoinBlock:          "bitcoin-block",
	BitcoinTx:             "bitcoin-tx",
	ZcashBlock:            "zcash-block",
	ZcashTx:               "zcash-tx",
	DecredBlock:           "decred-block",
	DecredTx:              "decred-tx",
	DashBlock:             "dash-block",
	DashTx:                "dash-tx",
	FilCommitmentUnsealed: "fil-commitment-unsealed",
	FilCommitmentSealed:   "fil-commitment-sealed",
}

func assertEqual(t *testing.T, a, b Cid) {
	if a.Type() != b.Type() {
		t.Fatal("mismatch on type")
	}

	if a.Version() != b.Version() {
		t.Fatal("mismatch on version")
	}

	if !bytes.Equal(a.Hash(), b.Hash()) {
		t.Fatal("multihash mismatch")
	}
}

func TestTable(t *testing.T) {
	if len(tCodecs) != len(Codecs)-1 {
		t.Errorf("Item count mismatch in the Table of Codec. Should be %d, got %d", len(tCodecs)+1, len(Codecs))
	}

	for k, v := range tCodecs {
		if Codecs[v] != k {
			t.Errorf("Table mismatch: 0x%x %s", k, v)
		}
	}
}

// The table returns cid.DagProtobuf for "v0"
// so we test it apart
func TestTableForV0(t *testing.T) {
	if Codecs["v0"] != DagProtobuf {
		t.Error("Table mismatch: Codecs[\"v0\"] should resolve to DagProtobuf (0x70)")
	}
}

func TestPrefixSum(t *testing.T) {
	// Test creating CIDs both manually and with Prefix.
	// Tests: https://github.com/ipfs/go-cid/issues/83
	for _, hashfun := range []uint64{
		mh.ID, mh.SHA3, mh.SHA2_256,
	} {
		h1, err := mh.Sum([]byte("TEST"), hashfun, -1)
		if err != nil {
			t.Fatal(err)
		}
		c1 := NewCidV1(Raw, h1)

		h2, err := mh.Sum([]byte("foobar"), hashfun, -1)
		if err != nil {
			t.Fatal(err)
		}
		c2 := NewCidV1(Raw, h2)

		c3, err := c1.Prefix().Sum([]byte("foobar"))
		if err != nil {
			t.Fatal(err)
		}
		if !c2.Equals(c3) {
			t.Fatal("expected CIDs to be equal")
		}
	}
}

func TestBasicMarshaling(t *testing.T) {
	h, err := mh.Sum([]byte("TEST"), mh.SHA3, 4)
	if err != nil {
		t.Fatal(err)
	}

	cid := NewCidV1(7, h)

	data := cid.Bytes()

	out, err := Cast(data)
	if err != nil {
		t.Fatal(err)
	}

	assertEqual(t, cid, out)

	s := cid.String()
	out2, err := Decode(s)
	if err != nil {
		t.Fatal(err)
	}

	assertEqual(t, cid, out2)
}

func TestBasesMarshaling(t *testing.T) {
	h, err := mh.Sum([]byte("TEST"), mh.SHA3, 4)
	if err != nil {
		t.Fatal(err)
	}

	cid := NewCidV1(7, h)

	data := cid.Bytes()

	out, err := Cast(data)
	if err != nil {
		t.Fatal(err)
	}

	assertEqual(t, cid, out)

	testBases := []mbase.Encoding{
		mbase.Base16,
		mbase.Base32,
		mbase.Base32hex,
		mbase.Base32pad,
		mbase.Base32hexPad,
		mbase.Base58BTC,
		mbase.Base58Flickr,
		mbase.Base64pad,
		mbase.Base64urlPad,
		mbase.Base64url,
		mbase.Base64,
	}

	for _, b := range testBases {
		s, err := cid.StringOfBase(b)
		if err != nil {
			t.Fatal(err)
		}

		if s[0] != byte(b) {
			t.Fatal("Invalid multibase header")
		}

		out2, err := Decode(s)
		if err != nil {
			t.Fatal(err)
		}

		assertEqual(t, cid, out2)

		encoder, err := mbase.NewEncoder(b)
		if err != nil {
			t.Fatal(err)
		}
		s2 := cid.Encode(encoder)
		if s != s2 {
			t.Fatalf("'%s' != '%s'", s, s2)
		}
	}
}

func TestBinaryMarshaling(t *testing.T) {
	data := []byte("this is some test content")
	hash, _ := mh.Sum(data, mh.SHA2_256, -1)
	c := NewCidV1(DagCBOR, hash)
	var c2 Cid

	data, err := c.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	err = c2.UnmarshalBinary(data)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Equals(c2) {
		t.Errorf("cids should be the same: %s %s", c, c2)
	}
}

func TestTextMarshaling(t *testing.T) {
	data := []byte("this is some test content")
	hash, _ := mh.Sum(data, mh.SHA2_256, -1)
	c := NewCidV1(DagCBOR, hash)
	var c2 Cid

	data, err := c.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	err = c2.UnmarshalText(data)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Equals(c2) {
		t.Errorf("cids should be the same: %s %s", c, c2)
	}
}

func TestEmptyString(t *testing.T) {
	_, err := Decode("")
	if err == nil {
		t.Fatal("shouldnt be able to parse an empty cid")
	}
}

func TestV0Handling(t *testing.T) {
	old := "QmdfTbBqBPQ7VNxZEYEj14VmRuZBkqFbiwReogJgS1zR1n"

	cid, err := Decode(old)
	if err != nil {
		t.Fatal(err)
	}

	if cid.Version() != 0 {
		t.Fatal("should have gotten version 0 cid")
	}

	if cid.Hash().B58String() != old {
		t.Fatalf("marshaling roundtrip failed: %s != %s", cid.Hash().B58String(), old)
	}

	if cid.String() != old {
		t.Fatal("marshaling roundtrip failed")
	}

	new, err := cid.StringOfBase(mbase.Base58BTC)
	if err != nil {
		t.Fatal(err)
	}
	if new != old {
		t.Fatal("StringOfBase roundtrip failed")
	}

	encoder, err := mbase.NewEncoder(mbase.Base58BTC)
	if err != nil {
		t.Fatal(err)
	}
	if cid.Encode(encoder) != old {
		t.Fatal("Encode roundtrip failed")
	}
}

func TestV0ErrorCases(t *testing.T) {
	badb58 := "QmdfTbBqBPQ7VNxZEYEj14VmRuZBkqFbiwReogJgS1zIII"
	_, err := Decode(badb58)
	if err == nil {
		t.Fatal("should have failed to decode that ref")
	}
}

func TestNewPrefixV1(t *testing.T) {
	data := []byte("this is some test content")

	// Construct c1
	prefix := NewPrefixV1(DagCBOR, mh.SHA2_256)
	c1, err := prefix.Sum(data)
	if err != nil {
		t.Fatal(err)
	}

	if c1.Prefix() != prefix {
		t.Fatal("prefix not preserved")
	}

	// Construct c2
	hash, err := mh.Sum(data, mh.SHA2_256, -1)
	if err != nil {
		t.Fatal(err)
	}
	c2 := NewCidV1(DagCBOR, hash)

	if !c1.Equals(c2) {
		t.Fatal("cids mismatch")
	}
	if c1.Prefix() != c2.Prefix() {
		t.Fatal("prefixes mismatch")
	}
}

func TestNewPrefixV0(t *testing.T) {
	data := []byte("this is some test content")

	// Construct c1
	prefix := NewPrefixV0(mh.SHA2_256)
	c1, err := prefix.Sum(data)
	if err != nil {
		t.Fatal(err)
	}

	if c1.Prefix() != prefix {
		t.Fatal("prefix not preserved")
	}

	// Construct c2
	hash, err := mh.Sum(data, mh.SHA2_256, -1)
	if err != nil {
		t.Fatal(err)
	}
	c2 := NewCidV0(hash)

	if !c1.Equals(c2) {
		t.Fatal("cids mismatch")
	}
	if c1.Prefix() != c2.Prefix() {
		t.Fatal("prefixes mismatch")
	}

}

func TestInvalidV0Prefix(t *testing.T) {
	tests := []Prefix{
		{
			MhType:   mh.SHA2_256,
			MhLength: 31,
		},
		{
			MhType:   mh.SHA2_256,
			MhLength: 33,
		},
		{
			MhType:   mh.SHA2_256,
			MhLength: -2,
		},
		{
			MhType:   mh.SHA2_512,
			MhLength: 32,
		},
		{
			MhType:   mh.SHA2_512,
			MhLength: -1,
		},
	}

	for i, p := range tests {
		t.Log(i)
		_, err := p.Sum([]byte("testdata"))
		if err == nil {
			t.Fatalf("should error (index %d)", i)
		}
	}

}

func TestPrefixRoundtrip(t *testing.T) {
	data := []byte("this is some test content")
	hash, _ := mh.Sum(data, mh.SHA2_256, -1)
	c := NewCidV1(DagCBOR, hash)

	pref := c.Prefix()

	c2, err := pref.Sum(data)
	if err != nil {
		t.Fatal(err)
	}

	if !c.Equals(c2) {
		t.Fatal("output didnt match original")
	}

	pb := pref.Bytes()

	pref2, err := PrefixFromBytes(pb)
	if err != nil {
		t.Fatal(err)
	}

	if pref.Version != pref2.Version || pref.Codec != pref2.Codec ||
		pref.MhType != pref2.MhType || pref.MhLength != pref2.MhLength {
		t.Fatal("input prefix didnt match output")
	}
}

func Test16BytesVarint(t *testing.T) {
	data := []byte("this is some test content")
	hash, _ := mh.Sum(data, mh.SHA2_256, -1)
	c := NewCidV1(1<<63, hash)
	_ = c.Bytes()
}

func TestFuzzCid(t *testing.T) {
	buf := make([]byte, 128)
	for i := 0; i < 200; i++ {
		s := rand.Intn(128)
		rand.Read(buf[:s])
		_, _ = Cast(buf[:s])
	}
}

func TestParse(t *testing.T) {
	cid, err := Parse(123)
	if err == nil {
		t.Fatalf("expected error from Parse()")
	}
	if !strings.Contains(err.Error(), "can't parse 123 as Cid") {
		t.Fatalf("expected int error, got %s", err.Error())
	}

	theHash := "QmdfTbBqBPQ7VNxZEYEj14VmRuZBkqFbiwReogJgS1zR1n"
	h, err := mh.FromB58String(theHash)
	if err != nil {
		t.Fatal(err)
	}

	assertions := [][]interface{}{
		[]interface{}{NewCidV0(h), theHash},
		[]interface{}{NewCidV0(h).Bytes(), theHash},
		[]interface{}{h, theHash},
		[]interface{}{theHash, theHash},
		[]interface{}{"/ipfs/" + theHash, theHash},
		[]interface{}{"https://ipfs.io/ipfs/" + theHash, theHash},
		[]interface{}{"http://localhost:8080/ipfs/" + theHash, theHash},
	}

	assert := func(arg interface{}, expected string) error {
		cid, err = Parse(arg)
		if err != nil {
			return err
		}
		if cid.Version() != 0 {
			return fmt.Errorf("expected version 0, got %s", fmt.Sprint(cid.Version()))
		}
		actual := cid.Hash().B58String()
		if actual != expected {
			return fmt.Errorf("expected hash %s, got %s", expected, actual)
		}
		actual = cid.String()
		if actual != expected {
			return fmt.Errorf("expected string %s, got %s", expected, actual)
		}
		return nil
	}

	for _, args := range assertions {
		err := assert(args[0], args[1].(string))
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestHexDecode(t *testing.T) {
	hexcid := "f015512209d8453505bdc6f269678e16b3e56c2a2948a41f2c792617cc9611ed363c95b63"
	c, err := Decode(hexcid)
	if err != nil {
		t.Fatal(err)
	}

	if c.String() != "bafkreie5qrjvaw64n4tjm6hbnm7fnqvcssfed4whsjqxzslbd3jwhsk3mm" {
		t.Fatal("hash value failed to round trip decoding from hex")
	}
}

func ExampleDecode() {
	encoded := "bafkreie5qrjvaw64n4tjm6hbnm7fnqvcssfed4whsjqxzslbd3jwhsk3mm"
	c, err := Decode(encoded)
	if err != nil {
		fmt.Printf("Error: %s", err)
		return
	}

	fmt.Println(c)
	// Output: bafkreie5qrjvaw64n4tjm6hbnm7fnqvcssfed4whsjqxzslbd3jwhsk3mm
}

func TestFromJson(t *testing.T) {
	cval := "bafkreie5qrjvaw64n4tjm6hbnm7fnqvcssfed4whsjqxzslbd3jwhsk3mm"
	jsoncid := []byte(`{"/":"` + cval + `"}`)
	var c Cid
	err := json.Unmarshal(jsoncid, &c)
	if err != nil {
		t.Fatal(err)
	}

	if c.String() != cval {
		t.Fatal("json parsing failed")
	}
}

func TestJsonRoundTrip(t *testing.T) {
	exp, err := Decode("bafkreie5qrjvaw64n4tjm6hbnm7fnqvcssfed4whsjqxzslbd3jwhsk3mm")
	if err != nil {
		t.Fatal(err)
	}

	// Verify it works for a *Cid.
	enc, err := json.Marshal(exp)
	if err != nil {
		t.Fatal(err)
	}
	var actual Cid
	err = json.Unmarshal(enc, &actual)
	if !exp.Equals(actual) {
		t.Fatal("cids not equal for *Cid")
	}

	// Verify it works for a Cid.
	enc, err = json.Marshal(exp)
	if err != nil {
		t.Fatal(err)
	}
	var actual2 Cid
	err = json.Unmarshal(enc, &actual2)
	if !exp.Equals(actual2) {
		t.Fatal("cids not equal for Cid")
	}
}

func BenchmarkStringV1(b *testing.B) {
	data := []byte("this is some test content")
	hash, _ := mh.Sum(data, mh.SHA2_256, -1)
	cid := NewCidV1(Raw, hash)

	b.ReportAllocs()
	b.ResetTimer()

	count := 0
	for i := 0; i < b.N; i++ {
		count += len(cid.String())
	}
	if count != 49*b.N {
		b.FailNow()
	}
}

func TestReadCidsFromBuffer(t *testing.T) {
	cidstr := []string{
		"bafkreie5qrjvaw64n4tjm6hbnm7fnqvcssfed4whsjqxzslbd3jwhsk3mm",
		"k2cwueckqkibutvhkr4p2ln2pjcaxaakpd9db0e7j7ax1lxhhxy3ekpv",
		"Qmf5Qzp6nGBku7CEn2UQx4mgN8TW69YUok36DrGa6NN893",
		"zb2rhZi1JR4eNc2jBGaRYJKYM8JEB4ovenym8L1CmFsRAytkz",
	}

	var cids []Cid
	var buf []byte
	for _, cs := range cidstr {
		c, err := Decode(cs)
		if err != nil {
			t.Fatal(err)
		}
		cids = append(cids, c)
		buf = append(buf, c.Bytes()...)
	}

	var cur int
	for _, expc := range cids {
		n, c, err := CidFromBytes(buf[cur:])
		if err != nil {
			t.Fatal(err)
		}
		if c != expc {
			t.Fatal("cids mismatched")
		}
		cur += n
	}
	if cur != len(buf) {
		t.Fatal("had trailing bytes")
	}
}

func TestBadParse(t *testing.T) {
	hash, err := mh.Sum([]byte("foobar"), mh.SHA3_256, -1)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Parse(hash)
	if err == nil {
		t.Fatal("expected to fail to parse an invalid CIDv1 CID")
	}
}

type Counter struct {
	count int
}

func (counter *Counter) String() string {
	return fmt.Sprintf("{count: %d}", counter.count)
}

var mapChan = make(chan map[string]*Counter, 5)

func TestGo(t *testing.T) {
	syncChan := make(chan struct{}, 2)
	go func() {
		for {
			if m, ok := <-mapChan; ok {
				counter := m["count"]
				counter.count++
			} else {
				break
			}
		}
		fmt.Println("Stopped.[receiver]")
		syncChan <- struct{}{}
	}()

	go func() {
		countMap := map[string]*Counter{"count": &Counter{}}
		for i := 0; i < 5; i++ {
			mapChan <- countMap
			time.Sleep(time.Millisecond)
			fmt.Printf("%v.[sender]\n", countMap)
		}
		close(mapChan)
		syncChan <- struct{}{}
	}()
	<-syncChan
	<-syncChan
}
