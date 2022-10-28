package bit_l

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"github.com/hashicorp/go-hclog"
	config "github.com/seafooler/BitFT/config"
	"github.com/seafooler/BitFT/sign"
	"strconv"
	"testing"
	"time"
)

var logger = hclog.New(&hclog.LoggerOptions{
	Name:   "BitFT-test",
	Output: hclog.DefaultOutput,
	Level:  hclog.Debug,
})

// set up a cluster environment for the testing
func setup(nodeNumber uint8, logLevel int, round int, batchSize int) ([]*Node, error) {
	names := make([]string, nodeNumber)
	clusterAddr := make(map[string]string, nodeNumber)
	clusterPort := make(map[string]int, nodeNumber)
	clusterAddrWithPorts := make(map[string]uint8)
	for i := 0; i < int(nodeNumber); i++ {
		name := fmt.Sprintf("node%d", i)
		names[i] = name
		clusterAddr[name] = "127.0.0.1"
		clusterPort[name] = 8000 + i
		clusterAddrWithPorts["127.0.0.1:"+strconv.Itoa(8000+i)] = uint8(i)
	}

	privKeys := make([]ed25519.PrivateKey, nodeNumber)
	pubKeys := make([]ed25519.PublicKey, nodeNumber)

	// create the ED25519 keys
	for i := 0; i < int(nodeNumber); i++ {
		privKeys[i], pubKeys[i] = sign.GenED25519Keys()
	}

	pubKeyMap := make(map[string]ed25519.PublicKey)
	for i := 0; i < int(nodeNumber); i++ {
		pubKeyMap[names[i]] = pubKeys[i]
	}

	// create the threshold keys
	numT := nodeNumber - nodeNumber/3
	shares, pubPoly := sign.GenTSKeys(int(numT), int(nodeNumber))

	if len(shares) != int(nodeNumber) {
		return []*Node{}, errors.New("number of generated private keys is incorrect")
	}

	confs := make([]*config.Config, nodeNumber)
	nodes := make([]*Node, nodeNumber)
	for i := 0; i < int(nodeNumber); i++ {
		confs[i] = config.New(names[i], 10, "127.0.0.1", clusterAddr, clusterPort, clusterAddrWithPorts, pubKeyMap,
			privKeys[i], pubPoly, shares[i], 1.0/float64(nodeNumber), 8000+i, 9000+i, logLevel, 0, round, batchSize)
		nodes[i] = NewNode(confs[i])
		if err := nodes[i].StartP2PListen(); err != nil {
			panic(err)
		}
		nodes[i].InitRBC(confs[i])
}

	for i := 0; i < int(nodeNumber); i++ {
		go nodes[i].EstablishP2PConns()
	}

	//Wait the all the connections to be established
	time.Sleep(time.Second)

	for i := 0; i < int(nodeNumber); i++ {
		go nodes[i].HandleMsgsLoop()
		if nodes[i].NodeType == 0 {
			go nodes[i].ProposeBlockLoop()
		}
		go nodes[i].ProcessConstructedBlockLoop()
		go nodes[i].ProcessConstructedVoteLoop()
	}

	return nodes, nil
}

func clean(nodes []*Node) {
	for _, n := range nodes {
		n.trans.GetStreamContext().Done()
		n.trans.Close()
		close(n.shutdownCh)
	}
}

func TestNormalCaseNodes(t *testing.T) {
	nodes, err := setup(4, 3, 100, 2000)
	if err != nil {
		t.Fatal(err)
	}

	//wait all nodes stop
	time.Sleep(15*time.Second)

	compareChainsIgnoreQC(nodes, t)
	logger.Info("all the nodes have the same chain", "blocks", nodes[0].chain.String())

	// close the connections
	clean(nodes)
}

// ancestor blocks may be committed by blocks of different heights in different nodes
// thus, ignore the QCs comparison
func compareChainsIgnoreQC(nodes []*Node, t *testing.T) {
	for i, node := range nodes {
		for j, node2 := range nodes {
			if i == j {
				continue
			}
			_, err := node.chain.EqualIgnoreQC(node2.chain)
			if err != nil {
				t.Fatalf("committed chain in node %d does not match with node %d, err: %v", i, j, err)
			}
		}
	}
}
