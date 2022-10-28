/*
Package config implements the type to pass the arguments to the node
and implements a function to load the parameters from a configuration file.
*/
package config

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"github.com/seafooler/BitFT/sign"
	"github.com/spf13/viper"
	"go.dedis.ch/kyber/v3/share"
	"strconv"
	"strings"
)

// Config defines a type to describe the configuration.
type Config struct {
	Name                 string
	MaxPool              int
	BatchSize            int
	ListenPort           int
	P2PListenPort        int
	RPCListenPort        int
	AddrStr              string
	ClusterAddr          map[string]string // map from name to address
	ClusterPort          map[string]int    // map from name to port
	ClusterAddrWithPorts map[string]uint8
	PublicKeyMap         map[string]ed25519.PublicKey
	PrivateKey           ed25519.PrivateKey
	TsPublicKey          *share.PubPoly
	TsPrivateKey         *share.PriShare
	Probability          float64
	LogLevel             int
	NodeType             int
	Round                int
	Protocol             string
}

// NewConfig creates a new variable of type Config from some arguments.
func New(name string, maxPool int, addrStr string, clusterAddr map[string]string, clusterPort map[string]int,
	clusterAddrWithPorts map[string]uint8, publicKeyMap map[string]ed25519.PublicKey, privateKey ed25519.PrivateKey,
	tsPublicKey *share.PubPoly, tsPrivateKey *share.PriShare, probability float64, p2PListenPort, rPCListenPort int,
	logLevel int, nodeType int, round int, batchSize int ) *Config {
	return &Config{
		Name:                 name,
		MaxPool:              maxPool,
		AddrStr:              addrStr,
		ClusterAddr:          clusterAddr,
		ClusterPort:          clusterPort,
		ClusterAddrWithPorts: clusterAddrWithPorts,
		PublicKeyMap:         publicKeyMap,
		PrivateKey:           privateKey,
		TsPublicKey:          tsPublicKey,
		TsPrivateKey:         tsPrivateKey,
		Probability:          probability,
		P2PListenPort:        p2PListenPort,
		RPCListenPort:        rPCListenPort,
		LogLevel:             logLevel,
		NodeType:             nodeType,
		Round:                round,
		BatchSize:            batchSize,
	}
}

// LoadConfig loads configuration files by package viper.
func LoadConfig(configPrefix, configName string) (*Config, error) {
	viperConfig := viper.New()

	// for environment variables
	viperConfig.SetEnvPrefix(configPrefix)
	viperConfig.AutomaticEnv()
	replacer := strings.NewReplacer(".", "_")
	viperConfig.SetEnvKeyReplacer(replacer)

	viperConfig.SetConfigName(configName)
	viperConfig.AddConfigPath("./")

	err := viperConfig.ReadInConfig()
	if err != nil {
		return nil, err
	}

	privKeyEDAsString := viperConfig.GetString("privkeyed")
	privKeyED, err := hex.DecodeString(privKeyEDAsString)
	if err != nil {
		return nil, err
	}

	tsPubKeyAsString := viperConfig.GetString("tspubkey")
	tsPubKeyAsBytes, err := hex.DecodeString(tsPubKeyAsString)
	if err != nil {
		return nil, err
	}
	tsPubKey, err := sign.DecodeTSPublicKey(tsPubKeyAsBytes)
	if err != nil {
		return nil, err
	}

	tsShareAsString := viperConfig.GetString("tsshare")
	tsShareAsBytes, err := hex.DecodeString(tsShareAsString)
	if err != nil {
		return nil, err
	}
	tsShareKey, err := sign.DecodeTSPartialKey(tsShareAsBytes)
	if err != nil {
		return nil, err
	}

	conf := &Config{
		Name:             viperConfig.GetString("name"),
		MaxPool:          viperConfig.GetInt("max_pool"),
		BatchSize:       viperConfig.GetInt("batch_size"),
		AddrStr:          viperConfig.GetString("address"),
		PrivateKey:       privKeyED,
		TsPublicKey:      tsPubKey,
		TsPrivateKey:     tsShareKey,
		P2PListenPort:    viperConfig.GetInt("p2p_listen_port"),
		RPCListenPort:    viperConfig.GetInt("rpc_listen_port"),
		LogLevel:         viperConfig.GetInt("log_level"),
		NodeType:         viperConfig.GetInt("nodetype"),
		Round:            viperConfig.GetInt("round"),
		Protocol:         viperConfig.GetString("protocol"),
	}

	peersP2PPortMapString := viperConfig.GetStringMap("peers_p2p_port")
	peersIPsMapString := viperConfig.GetStringMap("cluster_ips")

	pubKeyMapString := viperConfig.GetStringMap("cluster_pubkeyed")
	pubKeyMap := make(map[string]ed25519.PublicKey, len(pubKeyMapString))
	clusterAddr := make(map[string]string, len(pubKeyMapString))
	clusterPort := make(map[string]int, len(pubKeyMapString))
	clusterAddrWithPorts := make(map[string]uint8, len(pubKeyMapString))
	var i uint8 = 0
	for name, pkAsInterface := range pubKeyMapString {
		clusterPort[name] = peersP2PPortMapString[name].(int)
		clusterAddr[name] = peersIPsMapString[name].(string)
		if pkAsString, ok := pkAsInterface.(string); ok {
			pubKey, err := hex.DecodeString(pkAsString)
			if err != nil {
				return nil, err
			}
			pubKeyMap[name] = pubKey
		} else {
			return nil, errors.New("public key in the config file cannot be decoded correctly")
		}
		addrWithPort := peersIPsMapString[name].(string) + ":" + strconv.Itoa(peersP2PPortMapString[name].(int))
		idStr := name[4:]
		var id int
		if id, err = strconv.Atoi(idStr); err != nil {
			panic(err)
		}
		clusterAddrWithPorts[addrWithPort] = uint8(id)
		i++
	}

	conf.PublicKeyMap = pubKeyMap
	conf.ClusterPort = clusterPort
	conf.ClusterAddr = clusterAddr
	conf.Probability = viperConfig.GetFloat64("expectation") / float64(len(conf.ClusterAddr))
	conf.ClusterAddrWithPorts = clusterAddrWithPorts
	return conf, nil
}
