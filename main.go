package main

import (
	"errors"
	"github.com/seafooler/BitFT/bit"
	"github.com/seafooler/BitFT/bit_l"
	"github.com/seafooler/BitFT/config"
	"time"
)

var conf *config.Config
var err error

func init() {
	conf, err = config.LoadConfig("", "config")
	if err != nil {
		panic(err)
	}
}

func main() {
	if conf.Protocol == "bit" {
		runBitFT()
	} else if conf.Protocol == "bit_l" {
		runLayeredBitFT()
	} else {
		panic(errors.New("the protocol is unknown"))
	}
}

func runBitFT() {
	node := bit.NewNode(conf)
	if err = node.StartP2PListen(); err != nil {
		panic(err)
	}
	// wait for each node to start
	time.Sleep(time.Second * 10)
	if err = node.EstablishP2PConns(); err != nil {
		panic(err)

	}

	node.InitRBC(conf)
	if node.NodeType == 0 {
		go node.ProposeBlockLoop()
	}
	go node.HandleMsgsLoop()
	go node.ProcessConstructedBlockLoop()
	node.ProcessConstructedVoteLoop()
}

func runLayeredBitFT() {
	node := bit_l.NewNode(conf)
	if err = node.StartP2PListen(); err != nil {
		panic(err)
	}
	// wait for each node to start
	time.Sleep(time.Second * 10)
	if err = node.EstablishP2PConns(); err != nil {
		panic(err)

	}

	node.InitRBC(conf)
	if node.NodeType == 0 {
		go node.ProposeBlockLoop()
	}
	go node.HandleMsgsLoop()
	go node.ProcessConstructedBlockLoop()
	node.ProcessConstructedVoteLoop()
}