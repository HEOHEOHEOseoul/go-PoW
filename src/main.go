package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"time"
)

type Block struct {
	hash     []byte //블록 id
	prevHash []byte //이전 블록 아이디
	height   int64
	// nonce     int64
	timestamp time.Time
	// sign      []byte
	// txid      []byte
}

type blocks struct {
	blockchain map[[32]byte]*Block
}

var alreadyHasGene error = errors.New("already have genesis block")
var genesis *Block

func makeGenesis() (*Block, error) {
	if genesis != nil {
		fmt.Println("이미 제네시스 블록 있음")
		return nil, alreadyHasGene
	}
	genesis = &Block{[]byte("genesisHash"), []byte{}, 0, time.Now().UTC()}
	fmt.Println("제네시스 블록 생성 완료")
	return genesis, nil
}

func newBlock(prevHash []byte, h int64) (*Block, error) {
	// newB = &Block{[]byte("hashhash"), prevHash, h + 1, time.Now().UTC()}
	newB := &Block{}
	newB.hash = []byte("hashhash")
	newB.prevHash = prevHash
	newB.height = h + 1
	newB.timestamp = time.Now().UTC()

	return newB, nil
}

func (bs blocks) addBlock(b *Block) {
	bs.blockchain[b.hash] = b[:]
}

func newBlockChain(b *Block) (*blocks, error) {
	bs := &blocks{}
	bs.blockchain = make(map[[32]byte]*Block)
	fmt.Println("체인 생성 완료")
	genesis, err := makeGenesis()
	if err != nil {
		return nil, err
	}
	bs.blockchain[b.hash] = genesis
	fmt.Println(bs)
	return bs, nil
}

// func (b *Block) searchBlock(hash []byte) (*Block, error) {
// 	for i := range b {

// 	}

// }

func main() {
	// gene, err := makeGenesis()
	// fmt.Println(gene, err)
	test := sha256.Sum256([]byte("test"))
	for i := 0; i < len(test); i++ {
		fmt.Printf("%x", test[i])
	}

	fmt.Println()
	fmt.Println()
	fmt.Println()
	hi, errr := newBlock([]byte("genesisHash"), 0)

	fmt.Println()
	fmt.Println()
	fmt.Println()
	fmt.Println(string(hi.hash), errr)

	// fmt.Println(string(gene.hash))
	// --------------------------------
	newBlockChain()
	fmt.Println()
}

func IntToHex(a int64) []byte {

	return []byte{}
}
