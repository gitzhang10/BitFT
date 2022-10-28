/*
Package bit implements the bit protocol of BitFT,
including the data structures, votes, verification, and so on.
*/
package bit

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"github.com/hashicorp/go-hclog"
	"github.com/seafooler/BitFT/config"
	"github.com/seafooler/BitFT/conn"
	"github.com/seafooler/BitFT/rbc"
	"github.com/seafooler/BitFT/sign"
	"github.com/seafooler/BitFT/sortition"
	"go.dedis.ch/kyber/v3/share"
	"log"
	"math"
	"net"
	"net/http"
	"net/rpc"
	"reflect"
	"strconv"
	"sync"
	"time"
)

var proposal Block
var vote VoteWithPartialSig
var sortitionMsg sortition.SortitionMsg
var valMsg rbc.VALMsg
var echoMsg rbc.ECHOMsg
var readyMsg rbc.READYMsg

var reflectedTypesMap = map[uint8]reflect.Type{
	ProposalTag:  reflect.TypeOf(proposal),
	VoteTag:      reflect.TypeOf(vote),
	SortitionTag: reflect.TypeOf(sortitionMsg),
	RBCValTag:    reflect.TypeOf(valMsg),
	RBCEchoTag:   reflect.TypeOf(echoMsg),
	RBCReadyTag:  reflect.TypeOf(readyMsg),

}

// Node defines a node.
type Node struct {
	name                   string
	lock                   sync.RWMutex
	chain                  *Chain
	candidateChain         *CandidateChain
	candidateHeightUpdated chan uint64

	voted           map[uint64]bool
	pendingBlocksQC map[uint64]*BlockWithQC                 // map from height to the blockWithQC
	pendingBlocks   map[uint64]map[string]*Block            // map from height to the block, there may be multiple blocks for one height
	partialSigs     map[uint64]map[string]map[string][]byte // map from height to string(hash) to the partial signatures
	qcCreated       map[uint64]bool                         // mark if we has created a QC for the height
	isSortition     map[uint64]bool

	sortitionResult     map[uint64]map[uint64]map[string]bool // map from height to: map from [round] to: map from node to boolean
	sortitionResultLock sync.RWMutex
	sortitioner         *sortition.Sortitioner
	logger              hclog.Logger

	addr          string
	clusterAddr   map[string]string // map from name to address
	clusterPort   map[string]int    // map from name to p2pPort
	nodeNum       int               // record nodeNum and quorumNum to avoid repeated calculation
	quorumNum     int

	p2pListenPort int
	rpcListenPort int

	requestPool     *RequestPool
	c               *RPCHandler

	maxPool    int
	batchSize  int
	trans      *conn.NetworkTransport



	//Used for ED25519 signature
	publicKeyMap map[string]ed25519.PublicKey // after the initialization, only read, safe for concurrency safety
	privateKey   ed25519.PrivateKey

	//Used for threshold signature
	tsPublicKey  *share.PubPoly
	tsPrivateKey *share.PriShare

	reflectedTypesMap map[uint8]reflect.Type

	rbc                  *rbc.ReliableBroadcaster
	voterbc         	 *rbc.ReliableBroadcaster
	clusterAddrWithPorts map[string]uint8

	shutdownCh chan struct{}

	NodeType   int  //if the node is correct node, NodeType == 0
	round      int  // the total rounds the protocol will run
	evaluation []int64 // store the latency of every blocks
}

// NewNode creates a new node from a config.Config variable.
func NewNode(conf *config.Config) *Node {
	var n Node
	n.name = conf.Name
	n.addr = conf.AddrStr
	n.clusterAddr = conf.ClusterAddr
	n.clusterPort = conf.ClusterPort
	n.nodeNum = len(n.clusterAddr)
	n.quorumNum = int(math.Ceil(float64(2*len(n.clusterAddr)) / 3.0))
	n.maxPool = conf.MaxPool
	n.batchSize = conf.BatchSize

	n.p2pListenPort = conf.P2PListenPort
	n.rpcListenPort = conf.RPCListenPort

	n.requestPool = &RequestPool{}
	n.c = &RPCHandler{reqPool: n.requestPool, nodeName: n.name, nextSN: 0}

	n.chain = &Chain{height: 0, blocks: make(map[uint64]*BlockWithQC)}
	n.chain.blocks[0] = &BlockWithQC{
		Block: Block{
			Proposer:     "Seafooler&Iris",
			Height:       0,
			PreviousHash: []byte(""),
			Cmds:         []RequestWrappedByServer{},
		},
		QC: []byte(""),
	}
	n.candidateChain = &CandidateChain{height: 0, blocks: make(map[uint64]map[string]*Block)}
	block := n.chain.blocks[0].Block
	hash, _ := block.getHashAsString()
	n.candidateChain.blocks[0] = map[string]*Block{
		hash: &block,
	}
	n.candidateHeightUpdated = make(chan uint64, 1)
	n.candidateHeightUpdated <- 0
	n.voted = make(map[uint64]bool)

	n.pendingBlocksQC = make(map[uint64]*BlockWithQC)
	n.pendingBlocks = make(map[uint64]map[string]*Block)
	n.partialSigs = make(map[uint64]map[string]map[string][]byte)
	n.qcCreated = make(map[uint64]bool)
	n.isSortition = make(map[uint64]bool)

	n.sortitionResult = make(map[uint64]map[uint64]map[string]bool)

	n.logger = hclog.New(&hclog.LoggerOptions{
		Name:   "BitFT-node",
		Output: hclog.DefaultOutput,
		Level:  hclog.Level(conf.LogLevel),
	})

	sortitioner, err := sortition.NewSortitioner(conf.Probability, conf.PublicKeyMap[conf.Name], conf.PrivateKey)
	if err != nil {
		panic(err)
	}
	n.sortitioner = sortitioner

	n.privateKey = conf.PrivateKey
	n.publicKeyMap = conf.PublicKeyMap

	n.tsPrivateKey = conf.TsPrivateKey
	n.tsPublicKey = conf.TsPublicKey

	n.reflectedTypesMap = reflectedTypesMap
	n.shutdownCh = make(chan struct{})

	n.clusterAddrWithPorts = conf.ClusterAddrWithPorts

	n.NodeType = conf.NodeType
	n.round = conf.Round
	return &n
}

// EstablishP2PConns establishes P2P connections with other nodes.
func (n *Node) EstablishP2PConns() error {
	if n.trans == nil {
		return errors.New("networktransport has not been created")
	}
	for name, addr := range n.clusterAddr {
		addrWithPort := addr + ":" + strconv.Itoa(n.clusterPort[name])
		conn, err := n.trans.GetConn(addrWithPort)
		if err != nil {
			return err
		}
		n.trans.ReturnConn(conn)
		n.logger.Debug("connection has been established", "sender", n.name, "receiver", addr)
	}
	return nil
}

func (n *Node) InitRBC(conf *config.Config) {
	n.rbc = rbc.NewRBCer(n.name,"rbc", n.addr+":"+strconv.Itoa(n.p2pListenPort), conf.ClusterAddrWithPorts, rbcMsgType, n.trans,
		n.nodeNum-n.quorumNum, n.nodeNum, conf.LogLevel)
	n.voterbc = rbc.NewRBCer(n.name, "voterbc", n.addr+":"+strconv.Itoa(n.p2pListenPort), conf.ClusterAddrWithPorts, rbcMsgType, n.trans,
		n.nodeNum-n.quorumNum, n.nodeNum, conf.LogLevel)
}

// StartP2PListen starts the node to listen for P2P connection.
func (n *Node) StartP2PListen() error {
	var err error
	n.trans, err = conn.NewTCPTransport(":"+strconv.Itoa(n.clusterPort[n.name]), 20*time.Second,
		nil, n.maxPool, n.reflectedTypesMap)
	if err != nil {
		return err
	}
	n.logger.Info("Serving request listening", "addr", n.addr+":"+strconv.Itoa(n.p2pListenPort))
	return nil
}

// StartRPCListen starts the node to listen for requests from clients.
func (n *Node) StartRPCListen() error {
	err := rpc.Register(n.c)
	if err != nil {
		return err
	}
	rpc.HandleHTTP()
	listener, err := net.Listen("tcp", ":"+strconv.Itoa(n.rpcListenPort))
	if err != nil {
		log.Fatal("Request listen error: ", err)
	}

	n.logger.Info("Serving request listening", "addr", n.addr+":"+strconv.Itoa(n.rpcListenPort))

	go http.Serve(listener, nil)

	go func(l net.Listener) {
		<-n.shutdownCh
		l.Close()
	}(listener)

	return nil
}

// ProposeBlockLoop starts a loop to run BitFT
func (n *Node) ProposeBlockLoop() {
	var trans [20]byte
	var r = 0
	for i:=0;i<20;i++ {
		trans[i] = byte(i)
	}
	var batchTrans [][20]byte
	for i:=0; i<n.batchSize; i++ {
		batchTrans = append(batchTrans,trans)
	}

	start := time.Now().UnixNano()
	for {
		if r >= n.round {
			break
		}
		r++
		select {
		case <-n.shutdownCh:
			return
		case newHeight := <-n.candidateHeightUpdated:
			nextHeight := newHeight + 1
			if _, ok := n.sortitionResult[nextHeight]; !ok {
				n.sortitionResult[nextHeight] = make(map[uint64]map[string]bool)
			}
			for {
				if nextHeight <= n.candidateChain.height {
					break
				}
				n.sortitionResultLock.Lock()
				// find the largest round with 2/3+ false results
				maxRound := uint64(0)
				for round, results := range n.sortitionResult[nextHeight] {
					if len(results) >= n.quorumNum {
						if round > maxRound {
							maxRound = round
						}
					}
				}
				nextRound := maxRound + 1
				n.sortitionResultLock.Unlock()
				seedForSortition := nextHeight<<20 + nextRound // To do, 20 should be defined as an argument
				if n.isSortition[seedForSortition] == false {
					win, _ := n.sortitioner.Once(seedForSortition) // To do, proof handling ...
					n.isSortition[seedForSortition] = true
					if win {
						for {
							if nextHeight == 1 {
								break
							}
							num := 0
							// wait for 2f+1 votes for current height
							for _, parSigs := range n.partialSigs[nextHeight-1] {
								num += len(parSigs)
							}
							if num >= n.quorumNum {
								break
							}
							time.Sleep(time.Millisecond)
						}
						n.lock.Lock()
						previousBlock, err := n.selectBlock(nextHeight-1)
						n.lock.Unlock()
						if err != nil {
							panic(err)
						}
						previousHash, err := previousBlock.getHash()
						if err != nil {
							panic(err)
						}
						timestamp := time.Now().UnixNano()
						block := NewBlock(n.name, nextHeight, previousHash, nil)
						block.Trans = batchTrans
						block.TimeStamp = timestamp
						blockAsBytes, err := encode(block)
						if err != nil {
							panic(err)
						}
						if err := n.rbc.BroadcastVALMsg(n.privateKey, block.Height, blockAsBytes); err != nil {
							panic(err)
						}
						n.logger.Debug("Propose a new block", "Node", n.name, "blockHeight", block.Height,
							"round", nextRound, "batchSize", n.batchSize)
						break
					} else {
						sortitionMsg := sortition.NewSortitionMsg(n.name, nextHeight, nextRound)
						n.broadcast(SortitionTag, sortitionMsg, nil)
						n.logger.Debug("Sortition result false", "Node", n.name, "blockHeight", nextHeight,
							"round", nextRound)
					}
				} else {
					time.Sleep(time.Millisecond)
				}

			}
		}
	}
	end := time.Now().UnixNano()
	n.lock.Lock()
	pastTime := float64(end - start)/1e9
	blockNum := len(n.evaluation)
	throughPut := float64(blockNum * n.batchSize)/pastTime
	totalTime := int64(0)
	for _, t := range n.evaluation {
		totalTime += t
	}
	latency := float64(totalTime)/1e9/float64(blockNum)
	n.lock.Unlock()
	// wait for all nodes to finish
	time.Sleep(20*time.Second)
	n.logger.Info("the average", "latency", latency)
	n.logger.Info("the average", "throughput", throughPut)
}

// handleNewBlockQC handles a new block with QC.
// It simply adds the block with QC to the pendingBlocksQC,
// and call the function of tryExtendChain.
func (n *Node) handleNewBlockQC(bqc *BlockWithQC) {
	n.lock.Lock()
	if _, ok := n.pendingBlocksQC[bqc.Height]; ok {
		n.logger.Debug("a block with QC has been received before") // To be repaired ...: this check can be done at a former place
		return
	}
	n.pendingBlocksQC[bqc.Height] = bqc
	n.lock.Unlock()
	n.CommitAncestorByBlockQC(bqc)
	go n.tryExtendChain()
}

// CommitAncestorByBlockQC commits all the ancestor blocks of a block with QC.
func (n *Node) CommitAncestorByBlockQC(bqc *BlockWithQC) {
	n.lock.Lock()
	defer n.lock.Unlock()
	// all the ancestor blocks which can be committed must make up a prefix in the candidate chain
	// thus, we only need to check if the father block of bqc is in the candidate chain
	if len(n.chain.blocks) == len(n.candidateChain.blocks) {
		// if the candidate chain has a same length with chain, just do nothing
		// the extension of chain will be conducted in function tryExtendChain()
		return
	}
	previousHash := bqc.PreviousHash
	previousHeight := bqc.Height - 1
	if blocks, ok := n.candidateChain.blocks[previousHeight]; ok {
		for hashAsString, block := range blocks {
			if hashAsString == hex.EncodeToString(previousHash) {
				n.logger.Debug("previous blocks are successive", "Node", n.name, "blockWithQC", bqc.String(),
					"previousHeight", previousHeight, "candidateChainHeight", n.candidateChain.height,
					"chainHeight", n.chain.height)
				// commit the blocks from the candidate chain to the chain
				hash := hashAsString
				for i := previousHeight; i > n.chain.height; i-- {
					n.logger.Info("commit a block from candidate chain to the chain", "node",
						n.name, "height", i, "hash", hash)
					commitTime := time.Now().UnixNano()
					latency := commitTime - block.TimeStamp
					n.evaluation = append(n.evaluation, latency)
					n.chain.blocks[i] = &BlockWithQC{
						Block: *block,
						QC:    bqc.QC,
					}
					hash = hex.EncodeToString(block.PreviousHash)
					block, ok = n.candidateChain.blocks[i-1][hash]
					if !ok {
						n.logger.Error("no block in the candidateChain", "node", n.name, "height", i-1, "hash", hash)

					}
				}
				n.chain.height = previousHeight
			}
		}
	}
}

// tryExtendChain tries to extend the chain with blocks from pendingBlocksQC.
func (n *Node) tryExtendChain() {
	n.lock.Lock()
	defer n.lock.Unlock()
	newHeight := n.chain.height + 1
	if blockWithQC, ok := n.pendingBlocksQC[newHeight]; ok {
		n.chain.blocks[newHeight] = blockWithQC
		delete(n.pendingBlocksQC, newHeight)
		n.chain.height = newHeight
		n.logger.Info("commit the block", "node", n.name, "height", newHeight, "block-proposer", blockWithQC.Proposer)
		commitTime := time.Now().UnixNano()
		latency := commitTime - blockWithQC.TimeStamp
		n.evaluation = append(n.evaluation, latency)
		go n.tryExtendChain()
	}
}

// broadcast broadcasts the msg to each node, excluding the addrs in excAddrs.
func (n *Node) broadcast(msgType uint8, msg interface{}, excAddrs map[string]bool) error {
	msgAsBytes, err := encode(msg)
	if err != nil {
		return err
	}
	sig := sign.SignEd25519(n.privateKey, msgAsBytes)

	var netConn *conn.NetConn
	for name, addr := range n.clusterAddr {
		addrWithPort := addr + ":" + strconv.Itoa(n.clusterPort[name])
		if excAddrs != nil {
			if _, ok := excAddrs[addrWithPort]; ok {
				continue
			}
		}
		if netConn, err = n.trans.GetConn(addrWithPort); err != nil {
			return err
		}
		if err = conn.SendMsg(netConn, msgType, msg, sig); err != nil {
			return err
		}

		if err = n.trans.ReturnConn(netConn); err != nil {
			return err
		}
	}
	return nil
}

// signPlainVote signs the plain vote.
func (n *Node) signPlainVote(v *PlainVote) (*VoteWithPartialSig, error) {
	voteAsBytes, err := encode(v)
	if err != nil {
		return nil, err
	}
	partialSig := sign.SignTSPartial(n.tsPrivateKey, voteAsBytes)
	voteWithPartialSig := &VoteWithPartialSig{
		PlainVote:  *v,
		Sender:     n.name,
		PartialSig: partialSig,
	}
	return voteWithPartialSig, nil
}

// BroadcastVote broadcasts the vote for a block.
func (n *Node) BroadcastVote(block *Block) error {
	n.lock.RLock()
	if n.voted[block.Height] {
		// if has voted for another block with the same height, just return
		n.lock.RUnlock()
		return nil
	}
	n.lock.RUnlock()

	// construct vote
	hash, _ := block.getHash()
	plainVote := &PlainVote{
		BlockHash:   hash,
		BlockHeight: block.Height,
		Opinion:     true,
	}

	voteWithPartialSig, err := n.signPlainVote(plainVote)
	if err != nil {
		return err
	}

	n.lock.Lock()
	defer n.lock.Unlock()
	if !n.voted[block.Height] {
		n.logger.Debug("vote the block", "voter", n.name, "height", block.Height, "block-proposer", block.Proposer)
		n.voted[block.Height] = true
		voteASbytes, err := encode(voteWithPartialSig)
		if err != nil {
			panic(err)
		}
		// RBC the vote
		return n.voterbc.BroadcastVALMsg(n.privateKey, voteWithPartialSig.BlockHeight, voteASbytes)
	}
	return nil
}

func (n *Node) verifySigED25519(peer string, data interface{}, sig []byte) bool {
	pubKey, ok := n.publicKeyMap[peer]
	if !ok {
		n.logger.Error("peer is unknown", "peer", peer)
		return false
	}
	dataAsBytes, err := encode(data)
	if err != nil {
		n.logger.Error("fail to encode the data", "error", err)
		return false
	}
	ok, err = sign.VerifySignEd25519(pubKey, dataAsBytes, sig)
	if err != nil {
		n.logger.Error("fail to verify the ED25519 signature", "error", err)
		return false
	}
	return ok
}

// HandleMsgsLoop starts a loop to deal with the msgs from other peers.
func (n *Node) HandleMsgsLoop() {
	msgCh := n.trans.MsgChan()
	for {
		select {
		case msgWithSig := <-msgCh:
			switch msgAsserted := msgWithSig.Msg.(type) {
			case sortition.SortitionMsg:
				if !n.verifySigED25519(msgAsserted.Sortitioner, msgWithSig.Msg, msgWithSig.Sig) {
					n.logger.Error("fail to verify the sortitionmsg's signature", "height", msgAsserted.Height,
						"round", msgAsserted.Round, "sortitioner", msgAsserted.Sortitioner)
					continue
				}
				n.logger.Debug("signature of the sortitionmsg is right", "height", msgAsserted.Height,
					"round", msgAsserted.Round, "sortitioner", msgAsserted.Sortitioner)
				go n.handleSortitionMsg(&msgAsserted)
			case rbc.VALMsg:
				if !n.verifySigED25519(msgAsserted.Proposer, msgWithSig.Msg, msgWithSig.Sig) {
					n.logger.Error("fail to verify the VALMsg proposer's signature", "height", msgAsserted.DataSN,
						"proposer", msgAsserted.Proposer)
					continue
				}
				n.logger.Debug("signature of the VALMsg proposer is right", "height", msgAsserted.DataSN,
					"proposer", msgAsserted.Proposer, "proposer", msgAsserted.Proposer)
				if msgAsserted.Rbcname == "rbc" {
					go n.rbc.HandleRBCValMsg(n.privateKey, &msgAsserted)
				}
				if msgAsserted.Rbcname == "voterbc" {
					go n.voterbc.HandleRBCValMsg(n.privateKey, &msgAsserted)
				}
			case rbc.ECHOMsg:
				if !n.verifySigED25519(msgAsserted.Sender, msgWithSig.Msg, msgWithSig.Sig) {
					n.logger.Error("fail to verify the ECHOMsg sender's signature", "height", msgAsserted.DataSN,
						"proposer", msgAsserted.Proposer, "sender", msgAsserted.Sender)
					continue
				}
				n.logger.Debug("signature of the ECHOMsg sender is right", "height", msgAsserted.DataSN,
					"proposer", msgAsserted.Proposer, "sender", msgAsserted.Sender)
				addr := n.clusterAddr[msgAsserted.Sender]
				port := strconv.Itoa(n.clusterPort[msgAsserted.Sender])
				index, _ := n.clusterAddrWithPorts[addr+":"+port]
				if msgAsserted.Rbcname == "rbc" {
					go n.rbc.HandleRBCEchoMsg(n.privateKey, int(index), &msgAsserted)
				}
				if msgAsserted.Rbcname == "voterbc" {
					go n.voterbc.HandleRBCEchoMsg(n.privateKey, int(index), &msgAsserted)
				}
			case rbc.READYMsg:
				if !n.verifySigED25519(msgAsserted.Sender, msgWithSig.Msg, msgWithSig.Sig) {
					n.logger.Error("fail to verify the READYMsg sender's signature", "height", msgAsserted.DataSN,
						"proposer", msgAsserted.Proposer, "sender", msgAsserted.Sender)
					continue
				}
				n.logger.Debug("signature of the READYMsg sender is right", "height", msgAsserted.DataSN,
					"proposer", msgAsserted.Proposer, "sender", msgAsserted.Sender)
				if msgAsserted.Rbcname == "rbc" {
					go n.rbc.HandleRBCReadyMsg(n.privateKey, &msgAsserted)
				}
				if msgAsserted.Rbcname == "voterbc" {
					go n.voterbc.HandleRBCReadyMsg(n.privateKey, &msgAsserted)
				}

			}
		}
	}
}

func (n *Node) ProcessConstructedBlockLoop() {
	dataCh := n.rbc.ReturnDataChan()
	for {
		select {
		case data := <-dataCh:
			block := new(Block)
			if err := decode(data, block); err != nil {
				n.logger.Debug("Data received is not a block")
			} else {
				n.logger.Debug("Block is received by from RBC", "node", n.name, "height",
					block.Height, "proposer", block.Proposer)
				go n.handleNewBlockMsg(block)
			}
		}
	}
}

func (n *Node) ProcessConstructedVoteLoop() {
	dataCh := n.voterbc.ReturnDataChan()
	for {
		select {
		case data := <-dataCh:
			voteWithPartialSig := new(VoteWithPartialSig)
			if err := decode(data, voteWithPartialSig); err != nil {
				n.logger.Debug("Data received is not a vote")
			} else {
				n.logger.Debug("Vote is received by from RBC", "node", n.name, "height",
					voteWithPartialSig.BlockHeight, "proposer", voteWithPartialSig.Sender)
				go n.handleVoteMsg(voteWithPartialSig)
			}
		}
	}
}

// validateBlockMsg validates if the block msg is legal.
// To be repaired ...
// Just return true here.
func (n *Node) validateBlockMsg(block *Block) bool {
	return true
}

func (n *Node) handleNewBlockMsg(block *Block) {
	if ok := n.validateBlockMsg(block); !ok {
		// if the new vote message is illegal, ignore it
		return
	}
	go n.handleNewBlock(block)
	if n.NodeType == 0 {
		go n.BroadcastVote(block)
	}
}

func (n *Node) handleNewBlock(block *Block) {
	n.lock.Lock()
	defer n.lock.Unlock()
	if _, ok := n.pendingBlocks[block.Height]; !ok {
		n.pendingBlocks[block.Height] = make(map[string]*Block)
	}
	hash, _ := block.getHashAsString()
	n.pendingBlocks[block.Height][hash] = block
	go n.tryUpdateCandidateChain(block)
	go n.checkIfQuorumVotes(block.Height, hash)
}

// tryUpdateCandidateChain tries to update the candidate chain with blocks from pendingBlocks.
// If there is already a block with the same height, append the block;
// If there is no, extend the candidate chain.
func (n *Node) tryUpdateCandidateChain(block *Block) {
	n.lock.Lock()
	defer n.lock.Unlock()
	if _, ok := n.candidateChain.blocks[block.Height]; ok {
		// add the new block to existing height
		n.logger.Debug("add a new block to existing height", "height", block.Height, "block-proposer", block.Proposer)
		blockHashAsString, _ := block.getHashAsString()
		n.candidateChain.blocks[block.Height][blockHashAsString] = block
	} else {
		go n.tryExtendCandidateChain()
	}
}

func (n *Node) tryExtendCandidateChain() {
	n.lock.Lock()
	defer n.lock.Unlock()
	newHeight := n.candidateChain.height + 1
	if blocks, ok := n.pendingBlocks[newHeight]; ok {
		n.candidateChain.blocks[newHeight] = blocks
		n.candidateChain.height = newHeight
		go func() {
			n.candidateHeightUpdated <- newHeight
		}()
		n.logger.Debug("extend the height with blocks from pending blocks", "height", newHeight)
		go n.tryExtendCandidateChain()
	}
}

// validateVoteMsg Validates if the vote msg is legal.
// To be repaired ...
// Just return true here.
func (n *Node) validateVoteMsg(vote *VoteWithPartialSig) bool {
	return true
}

func (n *Node) handleVoteMsg(vote *VoteWithPartialSig) {
	if ok := n.validateVoteMsg(vote); !ok {
		// if the new vote message is illegal, ignore it
		return
	}
	n.lock.Lock()
	defer n.lock.Unlock()
	parSigs, ok := n.partialSigs[vote.BlockHeight]
	if !ok {
		n.partialSigs[vote.BlockHeight] = make(map[string]map[string][]byte)
		parSigs, _ = n.partialSigs[vote.BlockHeight]
	}
	hashString := hex.EncodeToString(vote.BlockHash)
	_, ok = parSigs[hashString]
	if !ok {
		n.partialSigs[vote.BlockHeight][hashString] = make(map[string][]byte)
	}

	n.partialSigs[vote.BlockHeight][hashString][vote.Sender] = vote.PartialSig
	go n.checkIfQuorumVotes(vote.BlockHeight, hashString)
}

func (n *Node) buildBlockWithQC(height uint64, hashString string) {
	n.lock.Lock()
	tmpBlock := n.pendingBlocks[height][hashString]
	block := *tmpBlock
	partialSigs := n.extractPartialSigs(height, hashString)
	n.lock.Unlock()
	hash, _ := block.getHash()
	n.logger.Debug("heights", "node", n.name, "original height", height, "block.Height", block.Height)
	plainVote := &PlainVote{
		BlockHash:   hash,
		BlockHeight: block.Height,
		Opinion:     true,
	}

	intactSig, err := createIntactSig(plainVote, partialSigs, n.tsPublicKey, n.quorumNum, n.nodeNum)
	if err != nil {
		return
	}
	blockWithQC := &BlockWithQC{
		Block: block,
		QC:    intactSig,
	}
	n.logger.Debug("create a QC", "node", n.name, "plainvote", plainVote, "qc", intactSig)
	n.logger.Debug("compare heights", "blockWithQC.Height", blockWithQC.Height, "block.Height", block.Height,
		"plainVote.BlockHeight", plainVote.BlockHeight)
	go n.handleNewBlockQC(blockWithQC)
}

// extractPartialSigs extracts inner elements of size: quorum.
// @return: [][]byte
func (n *Node) extractPartialSigs(height uint64, hashString string) [][]byte {
	var partialSigs [][]byte
	num := n.quorumNum
	for _, parSig := range n.partialSigs[height][hashString] {
		if num == 0 {
			break // only need quorumNum partial signatures
		}
		partialSigs = append(partialSigs, parSig)
		num--
	}
	return partialSigs
}

// checkIfQuorumVotes checks if there are votes of quorum for a block.
func (n *Node) checkIfQuorumVotes(height uint64, hashString string) {
	n.lock.Lock()
	parSigs, _ := n.partialSigs[height][hashString]
	_, ok := n.pendingBlocks[height][hashString]
	defer n.lock.Unlock()
	if len(parSigs) >= n.quorumNum && !n.qcCreated[height] && ok {
		n.qcCreated[height] = true
		go n.buildBlockWithQC(height, hashString)
	}
}

// handleSortitionMsg deals with the sortition message of 'false' result
func (n *Node) handleSortitionMsg(smsg *sortition.SortitionMsg) {
	n.sortitionResultLock.Lock()
	defer n.sortitionResultLock.Unlock()
	_, ok := n.sortitionResult[smsg.Height]
	if !ok {
		n.sortitionResult[smsg.Height] = make(map[uint64]map[string]bool)
	}
	_, ok = n.sortitionResult[smsg.Height][smsg.Round]
	if !ok {
		n.sortitionResult[smsg.Height][smsg.Round] = make(map[string]bool)
	}
	n.sortitionResult[smsg.Height][smsg.Round][smsg.Sortitioner] = false
}

//select a block with most votes in height h
func (n *Node) selectBlock(h uint64) (*Block, error) {
	if h == 0 {
		b := n.chain.blocks[0].Block
		return &b, nil
	}

	Blocks, ok := n.candidateChain.blocks[h]
	blocksCount := len(Blocks)
	if !ok || blocksCount == 0 {
		return nil, errors.New("no blocks in this height")
	}
	var votes = 0
	var block *Block
	for hash, b := range Blocks {
		if len(n.partialSigs[h][hash]) > votes {
			block = b
			votes = len(n.partialSigs[h][hash])
		}
	}
	return block, nil
}