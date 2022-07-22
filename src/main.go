package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math"
	"math/big"
	"reflect"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/ripemd160"
)

type Block struct { // 블록 구조체
	Hash      [32]byte
	prevHash  [32]byte
	PoW       [32]byte
	txid      [32]byte
	nonce     int
	height    int
	Data      []byte
	timestamp []byte
	sig       []byte
}

func NewBlock(prevHash [32]byte, height int) *Block {
	newBlock := &Block{}
	loc, _ := time.LoadLocation("Asia/Seoul")
	now := time.Now()
	t := now.In(loc)
	newBlock.prevHash = prevHash
	newBlock.timestamp = []byte(t.String()) // 시간을 스트링으로 변환하여 바이트 슬라이스에 넣음
	newBlock.Data = []byte("data")
	newPoW := newProofOfWork(newBlock)
	newBlock.nonce, newBlock.Hash = newPoW.Run()
	fmt.Printf("%d번째 블록 생성 %s\n\n", height, time.Now().String())
	return newBlock
}

func GenesisBlock() *Block {
	newBlock := &Block{}
	newBlock.height = 1
	loc, _ := time.LoadLocation("Asia/Seoul")
	now := time.Now()
	t := now.In(loc)
	newBlock.timestamp = []byte(t.String())
	newBlock.Data = []byte("GenesisBlock")
	newPoW := newProofOfWork(newBlock)
	newBlock.nonce, newBlock.Hash = newPoW.Run()
	fmt.Printf("제네시스 블록 생성 : %s\n\n", time.Now().String())
	return newBlock
}
func (b *Block) printBlock() {
	fmt.Println("-----블록체인 정보 출력 ----")
	fmt.Println("Hash: %x\nHeight: %d\nPrev Hash: %x\nNonce: %d\n%d\nPoW: %d\nTimeStamp: %d\nData: %s\nSign: %b\n", b.Hash, b.height, b.prevHash, b.nonce, b.PoW, b.timestamp, b.Data, b.sig)

}
func (b *Block) getBlockID() [32]byte {
	return b.Hash
}
func (b *Block) getHeight() int {
	return b.height
}
func (b *Block) get(txid []byte) [32]byte {
	if b.isExisted(txid) {
		return b.Hash
	} else {
		return [32]byte{}
	}
}

func (b *Block) isExisted(txid []byte) bool {
	return false
}

//--블록체인
type blocks struct {
	blockChain map[[32]byte]*Block
}

func newBlockChain(b *Block) *blocks {
	newBlocks := &blocks{}
	newBlocks.blockChain = make(map[[32]byte]*Block)
	newBlocks.blockChain[b.Hash] = b
	return newBlocks
}

func (bs *blocks) addBlock(o *Block) {
	currentHeight := len(bs.blockChain) // 블록개수 계산
	prev := [32]byte{}                  //제네시스 블록이 아니면 이전 블록 아이디 가져옴
	for _, value := range bs.blockChain {
		if value.height == currentHeight {
			prev = value.Hash
		}
	}
	o.prevHash = prev
	o.height = currentHeight + 1
	bs.blockChain[o.Hash] = o

}

func (bs *blocks) getBlock(blkId [32]byte) *Block {
	return bs.blockChain[blkId]
}
func (bs *blocks) findBlock(height int) *Block {
	//최신부터 돌려야해서 가장 최신 높이 구함
	if height == 0 {
		return nil
	}
	current_height := len(bs.blockChain)
	//최신 블록 아이디 찾기
	curBlockID := [32]byte{}
	for _, v := range bs.blockChain {
		if v.height == current_height {
			curBlockID = v.Hash
			break
		}
	}
	for {
		blk := bs.blockChain[curBlockID]
		if blk.height == height {
			return blk
		} else {
			if reflect.DeepEqual(blk.prevHash, [32]byte{}) {
				return nil
			}
			curBlockID = blk.prevHash
		}

	}
}

//-------PoW

var (
	maxNonce = math.MaxInt64
)

const targetBites = 20

type ProofOfWork struct {
	block  *Block
	target *big.Int
}

func IntToHex(obj int64) []byte {
	s := fmt.Sprint(obj)
	return []byte(s)
}
func (pow *ProofOfWork) prepareData(nonce int) []byte {
	data := bytes.Join([][]byte{
		pow.block.prevHash[:],
		pow.block.txid[:],
		pow.block.Data,
		pow.block.timestamp,
		IntToHex(int64(targetBites)),
		IntToHex(int64(nonce)),
	}, []byte{})
	return data
}
func (pow *ProofOfWork) Run() (int, [32]byte) {
	fmt.Printf("PoW 시작 -타겟비트 : 20 %s\n", time.Now().String())
	var hashInt big.Int
	var hash [32]byte
	nonce := 0

	for nonce < maxNonce {
		data := pow.prepareData(nonce)
		hash = sha256.Sum256(data)
		hashInt.SetBytes(hash[:])
		if hashInt.Cmp(pow.target) == -1 {
			break
		} else {
			nonce++
		}
	}
	fmt.Printf("PoW Run Finish: %s\n", time.Now().String())
	return nonce, hash
}

func newProofOfWork(block *Block) *ProofOfWork {

	target := big.NewInt(1)
	target.Lsh(target, uint(256-targetBites))
	pow := &ProofOfWork{block, target}

	return pow
}

//--tx
type Tx struct {
	TxID      [32]byte
	TimeStamp []byte //블럭생성시간
	Applier   []byte //신청자
	Company   []byte //일한회사
	Career    []byte //일한기간
	payment   []byte //결제수단
	Job       []byte //직종, 업무
	Proof     []byte //경력증명서 pdf
}

//Tx Hash 데이터 생성
func (tx *Tx) prepareData() []byte {
	data := bytes.Join([][]byte{
		tx.TimeStamp,
		tx.payment,
		tx.Applier,
		tx.Company,
		tx.Career,
		tx.Job,
		tx.Proof,
	}, []byte{})
	return data
}
func newTx(applier, company, career, payment, job, proof string) [32]byte {
	newTx := &Tx{}
	newTx.Applier = []byte(applier)
	newTx.Company = []byte(company)
	newTx.Career = []byte(career)
	newTx.payment = []byte(payment)
	newTx.Job = []byte(job)
	newTx.Proof = []byte(proof)
	loc, _ := time.LoadLocation("Asia/Seoul")
	now := time.Now()
	t := now.In(loc)
	newTx.TimeStamp = []byte(t.String())
	data := newTx.prepareData()
	newTx.TxID = sha256.Sum256(data)
	return newTx.TxID
}

//-----지갑생성
type wallet struct {
	privateKey ecdsa.PrivateKey
	publicKet  []byte
	Address    string
	Alias      string
}
type wallets struct {
	walletList map[string]*wallet
}

func main() {
	// prvKey, pubKey := newKeyPair() //키페어 한쌍을 만들고
	// fmt.Printf("%#v\n", prvKey)
	// fmt.Printf("%#v\n", pubKey)

	// encoded := base58.Encode(pubKey) //퍼블릭키를
	// fmt.Println(encoded)
	// decoded := base58.Decode(encoded)
	// if bytes.Equal(pubKey, decoded) {
	// 	fmt.Println("Same")
	// } else {
	// 	fmt.Println("Not same")
	// }

}

func newKeyPair() (ecdsa.PrivateKey, []byte) {
	curve := elliptic.P256()
	prvKey, _ := ecdsa.GenerateKey(curve, rand.Reader)
	pubKey := prvKey.PublicKey
	bpubKey := append(pubKey.X.Bytes(), pubKey.Y.Bytes()...)
	return *prvKey, bpubKey
}
func HashPubKey(pubKey []byte) []byte {
	publicSHA256 := sha256.Sum256(pubKey)
	RIPEMD160Hasher := ripemd160.New()
	RIPEMD160Hasher.Write(publicSHA256[:])
	publicRIPEMD160 := RIPEMD160Hasher.Sum(nil)
	return publicRIPEMD160
}

func newAddress() wallet {
	prvKey, pubKey := newKeyPair()
	fmt.Println(string(pubKey))
	rip := HashPubKey(pubKey)

	bas := base58.CheckEncode(rip, 0x00)
	fmt.Println(bas)
	newWallet := &wallet{prvKey, pubKey, bas}
	return prvKey, pubKey, bas

}

func (w *wallets) addAddress() {
	pri, pub, add := newAddress()

}

//--------------------

// package main

// import (
// 	"crypto/sha256"
// 	"errors"
// 	"fmt"
// 	"time"
// )

// type Block struct {
// 	hash     []byte //블록 id
// 	prevHash []byte //이전 블록 아이디
// 	height   int64
// 	// nonce     int64
// 	timestamp time.Time
// 	// sign      []byte
// 	// txid      []byte
// }

// type blocks struct {
// 	blockchain map[[32]byte]*Block
// }

// var alreadyHasGene error = errors.New("already have genesis block")
// var genesis *Block

// func makeGenesis() (*Block, error) {
// 	if genesis != nil {
// 		fmt.Println("이미 제네시스 블록 있음")
// 		return nil, alreadyHasGene
// 	}
// 	genesis = &Block{[]byte("genesisHash"), []byte{}, 0, time.Now().UTC()}
// 	fmt.Println("제네시스 블록 생성 완료")
// 	return genesis, nil
// }

// func newBlock(prevHash []byte, h int64) (*Block, error) {
// 	// newB = &Block{[]byte("hashhash"), prevHash, h + 1, time.Now().UTC()}
// 	newB := &Block{}
// 	newB.hash = []byte("hashhash")
// 	newB.prevHash = prevHash
// 	newB.height = h + 1
// 	newB.timestamp = time.Now().UTC()

// 	return newB, nil
// }

// func (bs blocks) addBlock(b *Block) {
// 	bs.blockchain[b.hash] = b[:]
// }

// func newBlockChain(b *Block) (*blocks, error) {
// 	bs := &blocks{}
// 	bs.blockchain = make(map[[32]byte]*Block)
// 	fmt.Println("체인 생성 완료")
// 	genesis, err := makeGenesis()
// 	if err != nil {
// 		return nil, err
// 	}
// 	bs.blockchain[b.hash] = genesis
// 	fmt.Println(bs)
// 	return bs, nil
// }

// // func (b *Block) searchBlock(hash []byte) (*Block, error) {
// // 	for i := range b {

// // 	}

// // }

// func main() {
// 	// gene, err := makeGenesis()
// 	// fmt.Println(gene, err)
// 	test := sha256.Sum256([]byte("test"))
// 	for i := 0; i < len(test); i++ {
// 		fmt.Printf("%x", test[i])
// 	}

// 	fmt.Println()
// 	fmt.Println()
// 	fmt.Println()
// 	hi, errr := newBlock([]byte("genesisHash"), 0)

// 	fmt.Println()
// 	fmt.Println()
// 	fmt.Println()
// 	fmt.Println(string(hi.hash), errr)

// 	// fmt.Println(string(gene.hash))
// 	// --------------------------------
// 	newBlockChain()
// 	fmt.Println()
// }

// func IntToHex(a int64) []byte {

// 	return []byte{}
// }
