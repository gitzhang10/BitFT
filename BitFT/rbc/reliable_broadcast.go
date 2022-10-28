package rbc

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"github.com/hashicorp/go-hclog"
	"github.com/seafooler/BitFT/conn"
	"github.com/seafooler/BitFT/sign"
	"sync"
)

type RbcMsgType map[string]uint8

type ReliableBroadcaster struct {
	addrWithPort         string
	clusterAddrWithPorts map[string]uint8
	connPool             *conn.NetworkTransport
	msgTypes             RbcMsgType
	f                    int
	n                    int
	cacheLock            sync.Mutex
	echoCountMM          map[uint64]map[string]int
	readyCountMM         map[uint64]map[string]int
	readySentMM          map[uint64]map[string]bool             // mark if the `ready` msg has been sent
	reconstructedMM      map[uint64]map[string]bool             // mark if the data has been reconstructed
	shardCacheMMM        map[uint64]map[string]map[uint8][]byte // cache the data for each shard, (dataID):(proposerID:(index, shard))
	hashCacheMM          map[uint64]map[string][]byte
	dataLenCacheMM       map[uint64]map[string]uint64

	name   string
	rbcName string
	logger hclog.Logger
	dataCh chan []byte
}

func (rbcer *ReliableBroadcaster) ReturnDataChan() chan []byte {
	return rbcer.dataCh
}

func NewRBCer(name, rbcname, addrWithPort string, clusterAddrWithPorts map[string]uint8, msgTypes RbcMsgType, connPool *conn.NetworkTransport,
	f, n, logLevel int) *ReliableBroadcaster {
	return &ReliableBroadcaster{
		name:                 name,
		rbcName:              rbcname,
		addrWithPort:         addrWithPort,
		clusterAddrWithPorts: clusterAddrWithPorts,
		connPool:             connPool,
		msgTypes:             msgTypes,
		f:                    f,
		n:                    n,
		echoCountMM:          make(map[uint64]map[string]int),
		readyCountMM:         make(map[uint64]map[string]int),
		readySentMM:          make(map[uint64]map[string]bool),
		reconstructedMM:      make(map[uint64]map[string]bool),
		shardCacheMMM:        make(map[uint64]map[string]map[uint8][]byte),
		hashCacheMM:          make(map[uint64]map[string][]byte),
		dataLenCacheMM:       make(map[uint64]map[string]uint64),

		logger: hclog.New(&hclog.LoggerOptions{
			Name:   "BitFT-rbc",
			Output: hclog.DefaultOutput,
			Level:  hclog.Level(logLevel),
		}),
		dataCh: make(chan []byte),
	}
}

// @dataID: e.g., block height in the blockchain scenario
func (rbcer *ReliableBroadcaster) BroadcastVALMsg(priKey ed25519.PrivateKey, dataSN uint64, data []byte) error {
	connPool := rbcer.connPool

	// encode the data into n shards
	shards, err := encode(data, rbcer.n-rbcer.f, rbcer.f)
	if err != nil {
		return err
	}

	tree, err := buildMerkleTree(shards)
	if err != nil {
		return err
	}

	rootHash := tree[1]

	branches := make(map[uint8][][]byte, rbcer.n)
	for i := 0; i < rbcer.n; i++ {
		branches[uint8(i)], err = getMerkleBranch(tree, i)
		if err != nil {
			return err
		}
	}

	// phase 1: broadcast the 'VAL' msgs
	msgType, ok := rbcer.msgTypes["VAL"]
	if !ok {
		return errors.New("type of 'VAL' is not defined")
	}
	for addrWithPort, i := range rbcer.clusterAddrWithPorts {
		netConn, err := connPool.GetConn(addrWithPort)
		if err != nil {
			return err
		}
		valMsg := VALMsg{
			Rbcname:      rbcer.rbcName,
			Proposer:     rbcer.name,
			DataSN:       dataSN,
			DataLen:      uint64(len(data)),
			RootHash:     rootHash,
			MerkleBranch: branches[i],
			ShardData:    shards[i],
		}

		msgAsBytes, err := encodeBytes(valMsg)
		if err != nil {
			return err
		}
		sig := sign.SignEd25519(priKey, msgAsBytes)

		if err = conn.SendMsg(netConn, msgType, valMsg, sig); err != nil {
			return err
		}

		if err = connPool.ReturnConn(netConn); err != nil {
			return err
		}

	}
	return nil
}



func (rbcer *ReliableBroadcaster) HandleRBCValMsg(priKey ed25519.PrivateKey, msg *VALMsg) error {
	connPool := rbcer.connPool

	// phase 2: broadcast the 'ECHO' msgs
	msgType, ok := rbcer.msgTypes["ECHO"]
	if !ok {
		return errors.New("type of 'ECHO' is not defined")
	}
	echoMsg := ECHOMsg{
		Rbcname:      rbcer.rbcName,
		Sender:       rbcer.name,
		Proposer:     msg.Proposer,
		DataSN:       msg.DataSN,
		DataLen:      msg.DataLen,
		RootHash:     msg.RootHash,
		MerkleBranch: msg.MerkleBranch,
		ShardData:    msg.ShardData,
	}

	msgAsBytes, err := encodeBytes(echoMsg)
	if err != nil {
		return err
	}
	sig := sign.SignEd25519(priKey, msgAsBytes)

	for addrWithPort, _ := range rbcer.clusterAddrWithPorts {
		netConn, err := connPool.GetConn(addrWithPort)
		if err != nil {
			return err
		}
		if err = conn.SendMsg(netConn, msgType, echoMsg, sig); err != nil {
			return err
		}

		if err = connPool.ReturnConn(netConn); err != nil {
			return err
		}
	}
	return nil
}

// Initialize the map structures
func (rbcer *ReliableBroadcaster) InitMapStructures(dataSN uint64, proposer string) {
	shardCacheMM, ok := rbcer.shardCacheMMM[dataSN]
	if !ok {
		rbcer.shardCacheMMM[dataSN] = make(map[string]map[uint8][]byte)
		shardCacheMM, _ = rbcer.shardCacheMMM[dataSN]
	}
	_, ok = shardCacheMM[proposer]
	if !ok {
		rbcer.shardCacheMMM[dataSN][proposer] = make(map[uint8][]byte)
	}

	_, ok = rbcer.echoCountMM[dataSN]
	if !ok {
		rbcer.echoCountMM[dataSN] = make(map[string]int)
	}

	_, ok = rbcer.hashCacheMM[dataSN]
	if !ok {
		rbcer.hashCacheMM[dataSN] = make(map[string][]byte)
	}

	_, ok = rbcer.dataLenCacheMM[dataSN]
	if !ok {
		rbcer.dataLenCacheMM[dataSN] = make(map[string]uint64)
	}

	_, ok = rbcer.readySentMM[dataSN]
	if !ok {
		rbcer.readySentMM[dataSN] = make(map[string]bool)
	}

	_, ok = rbcer.reconstructedMM[dataSN]
	if !ok {
		rbcer.reconstructedMM[dataSN] = make(map[string]bool)
	}
}

// To be repaired: the `index` should be protected by Merkle tree
func (rbcer *ReliableBroadcaster) HandleRBCEchoMsg(priKey ed25519.PrivateKey, index int, msg *ECHOMsg) error {
	if len(msg.MerkleBranch) == 0 {
		rbcer.logger.Error("merkle branch is empty", "node", rbcer.name, "dataSN", msg.DataSN,
			"proposer", msg.Proposer, "sender", msg.Sender)
		return errors.New("merkle branch is empty")
	}
	dataHash := genMsgHashSum(msg.ShardData)
	if !bytes.Equal(dataHash, msg.MerkleBranch[0]) {
		rbcer.logger.Error("shard data does not match the merkle branch", "node", rbcer.name, "dataSN",
			msg.DataSN, "proposer", msg.Proposer, "sender", msg.Sender)
		return errors.New("shard data does not match the merkle branch")
	}
	calcRootHash, err := rootFromMerkleBranch(msg.MerkleBranch, index)
	if err != nil {
		rbcer.logger.Error("calcRootHash error", "node", rbcer.name, "dataSN", msg.DataSN,
			"proposer", msg.Proposer, "sender", msg.Sender)
		return err
	}

	if !bytes.Equal(msg.RootHash, calcRootHash) {
		rbcer.logger.Error("merkle branch does not match the root hash", "node", rbcer.name, "dataSN",
			msg.DataSN, "proposer", msg.Proposer, "sender", msg.Sender, "EchoMsg", *msg)
		return errors.New("the merkle branch does not match the root hash")
	}

	//check against and update the cache
	rbcer.cacheLock.Lock()
	defer rbcer.cacheLock.Unlock()

	rbcer.InitMapStructures(msg.DataSN, msg.Proposer)

	// if `val` msgs with the same ID and sender are received multiple times, the latter one will replace the former
	rbcer.shardCacheMMM[msg.DataSN][msg.Proposer][uint8(index)] = msg.ShardData

	// deal with the echo Counter
	echoCount := rbcer.echoCountMM[msg.DataSN][msg.Proposer]
	rbcer.echoCountMM[msg.DataSN][msg.Proposer] = echoCount + 1

	// store the hash and datalength
	rbcer.hashCacheMM[msg.DataSN][msg.Proposer] = msg.RootHash

	rbcer.dataLenCacheMM[msg.DataSN][msg.Proposer] = msg.DataLen

	if echoCount+1 >= rbcer.n-rbcer.f && !rbcer.readySentMM[msg.DataSN][msg.Proposer] {
		rbcer.readySentMM[msg.DataSN][msg.Proposer] = true
		go rbcer.BroadcastReadyMsg(priKey, msg.DataSN, msg.Proposer, msg.RootHash)
	}

	go rbcer.reconstructData(msg.DataSN, msg.Proposer, msg.DataLen)

	return nil
}

// reconstruct the data from locally cached shards
func (rbcer *ReliableBroadcaster) reconstructData(dataID uint64, proposer string,
	dataLen uint64) ([]byte, error) {

	rbcer.cacheLock.Lock()
	if rbcer.readyCountMM[dataID][proposer] < rbcer.n-rbcer.f {
		rbcer.logger.Debug("Not enough ready messages", "node", rbcer.name, "dataID", dataID,
			"proposer", proposer, "rbc.readyCountMM[dataID][proposer]", rbcer.readyCountMM[dataID][proposer])
		rbcer.cacheLock.Unlock()
		return nil, errors.New("not enough ready messages")
	}

	if len(rbcer.shardCacheMMM[dataID][proposer]) < rbcer.n-rbcer.f {
		rbcer.logger.Debug("Not enough shards", "node", rbcer.name, "dataID", dataID, "proposer", proposer,
			"len(rbc.shardCacheMMM[dataID][proposer])", len(rbcer.shardCacheMMM[dataID][proposer]))
		rbcer.cacheLock.Unlock()
		return nil, errors.New("not enough shards")
	}

	if rbcer.reconstructedMM[dataID][proposer] {
		rbcer.logger.Debug("Data has been reconstructed before", "node", rbcer.name, "dataID", dataID,
			"proposer", proposer)
		rbcer.cacheLock.Unlock()
		return nil, errors.New("data has been reconstructed before")
	} else {
		rbcer.reconstructedMM[dataID][proposer] = true
		rbcer.cacheLock.Unlock()
	}

	// prepare the shards
	shards := make([][]byte, rbcer.n)
	for i := 0; i < rbcer.n; i++ {
		shards[i] = nil
	}

	rbcer.cacheLock.Lock()
	for index, shard := range rbcer.shardCacheMMM[dataID][proposer] {
		shards[index] = shard
	}
	rbcer.cacheLock.Unlock()

	// reconstruct data
	data, err := decode(shards, rbcer.n-rbcer.f, rbcer.f, int(dataLen))
	if err != nil {
		return nil, err
	}
	if len(data) != int(dataLen) {
		return nil, errors.New("the data reconstructed has a different length")
	}
	rbcer.logger.Debug("Data is reconstructed successfully", "node", rbcer.name, "sn", dataID,
		"proposer", proposer, "data", data)
	rbcer.dataCh <- data
	return data, nil
}

func (rbcer *ReliableBroadcaster) BroadcastReadyMsg(priKey ed25519.PrivateKey, dataSN uint64, proposerAddr string, rootHash []byte) error {
	connPool := rbcer.connPool
	// phase 3: broadcast the 'READY' msgs
	msgType, ok := rbcer.msgTypes["READY"]
	if !ok {
		return errors.New("type of 'READY' is not defined")
	}

	readyMsg := READYMsg{
		Rbcname:  rbcer.rbcName,
		Sender:   rbcer.name,
		Proposer: proposerAddr,
		DataSN:   dataSN,
		RootHash: rootHash,
	}

	msgAsBytes, err := encodeBytes(readyMsg)
	if err != nil {
		return err
	}
	sig := sign.SignEd25519(priKey, msgAsBytes)

	for addrWithPort, _ := range rbcer.clusterAddrWithPorts {
		netConn, err := connPool.GetConn(addrWithPort)
		if err != nil {
			return err
		}
		if err = conn.SendMsg(netConn, msgType, readyMsg, sig); err != nil {
			return err
		}

		if err = connPool.ReturnConn(netConn); err != nil {
			return err
		}
	}

	return nil
}

func (rbcer *ReliableBroadcaster) HandleRBCReadyMsg(priKey ed25519.PrivateKey, msg *READYMsg) error {
	rbcer.logger.Debug("Receive a ready message", "node", rbcer.name, "dataID", msg.DataSN,
		"proposer", msg.Proposer)
	rbcer.cacheLock.Lock()
	defer rbcer.cacheLock.Unlock()
	// check the rootHash
	rbcer.InitMapStructures(msg.DataSN, msg.Proposer)
	if bytes.Equal(rbcer.hashCacheMM[msg.DataSN][msg.Proposer], []byte{}) {
		rbcer.hashCacheMM[msg.DataSN][msg.Proposer] = msg.RootHash
	} else if !bytes.Equal(msg.RootHash, rbcer.hashCacheMM[msg.DataSN][msg.Proposer]) {
		return errors.New("the ready msg does not match the cache")
	}

	dataLen := rbcer.dataLenCacheMM[msg.DataSN][msg.Proposer]

	// deal with the Counter
	readyCountM, ok := rbcer.readyCountMM[msg.DataSN]
	if !ok {
		rbcer.readyCountMM[msg.DataSN] = make(map[string]int)
		readyCountM, _ = rbcer.readyCountMM[msg.DataSN]
	}
	readyCount, ok := readyCountM[msg.Proposer]
	if !ok {
		rbcer.readyCountMM[msg.DataSN][msg.Proposer] = 1
	} else {
		rbcer.readyCountMM[msg.DataSN][msg.Proposer] = readyCount + 1
	}

	rbcer.logger.Debug("ready count", "count", rbcer.readyCountMM[msg.DataSN][msg.Proposer],
		"node", rbcer.name, "dataSN", msg.DataSN, "proposer", msg.Proposer)

	if readyCount+1 >= rbcer.f+1 && !rbcer.readySentMM[msg.DataSN][msg.Proposer] {
		rbcer.readySentMM[msg.DataSN][msg.Proposer] = true
		// amplify the ready messages
		go rbcer.BroadcastReadyMsg(priKey, msg.DataSN, msg.Proposer, msg.RootHash)
	}

	go rbcer.reconstructData(msg.DataSN, msg.Proposer, dataLen)

	//if readyCount+1 >= rbc.n - rbc.f && !rbc.reconstructedMM[msg.DataSN][msg.Proposer] {
	//	rbc.reconstructedMM[msg.DataSN][msg.Proposer] = true
	//	go rbc.reconstructData(msg.DataSN, msg.Proposer, dataLen)
	//}

	return nil
}
