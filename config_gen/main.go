/*
Package main in the directory config_gen implements a tool to read configuration from a template,
and generate customized configuration files for each node.
The generated configuration file particularly contains the public/private keys for TS and ED25519.
*/
package main

import (
	"encoding/hex"
	"fmt"
	"github.com/seafooler/BitFT/sign"
	"github.com/spf13/viper"
	"math/rand"
	"sort"
	"strconv"
	"strings"
	"time"
)

func judgeNodeType(i int,b []int)bool{
	for _, v := range b {
		if i == v {
			return true
		}
	}
	return false
}

func generateRandomNumber(start int, end int, count int) []int {
	//范围检查
	if end < start || (end-start) < count {
		return nil
	}

	//存放结果的slice
	nums := make([]int, 0)
	//随机数生成器，加入时间戳保证每次生成的随机数不一样
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for len(nums) < count {
		//生成随机数
		num := r.Intn((end - start)) + start

		//查重
		exist := false
		for _, v := range nums {
			if v == num {
				exist = true
				break
			}
		}

		if !exist {
			nums = append(nums, num)
		}
	}
	return nums
}

func main() {

	viperRead := viper.New()

	// for environment variables
	viperRead.SetEnvPrefix("")
	viperRead.AutomaticEnv()
	replacer := strings.NewReplacer(".", "_")
	viperRead.SetEnvKeyReplacer(replacer)

	viperRead.SetConfigName("config_template")
	viperRead.AddConfigPath("./")

	err := viperRead.ReadInConfig()
	if err != nil {
		panic(err)
	}

	leaderCount:=1
	ProcessCount:=1   //调整节点数

	// deal with cluster as a string map
	ClusterMapInterface := viperRead.GetStringMap("ips")
	clusterMapInterface:= make(map[string]string)
	for name, addr := range ClusterMapInterface {
		rs := []rune(name)
		ipIndex,_ := strconv.Atoi(string(rs[4:]))
		if addrAsString, ok := addr.(string); ok {

			for j:=0;j<ProcessCount;j++{
				if ipIndex==0{
					for k:=0;k<leaderCount;k++{
						suScript:=strconv.Itoa(k)
						clusterMapInterface["node"+suScript]=addrAsString
					}
					break
				}
				suScript:=strconv.Itoa((ipIndex-1)*ProcessCount+j+leaderCount)
				clusterMapInterface["node"+suScript]=addrAsString
			}

		} else {
			panic("cluster in the config file cannot be decoded correctly")
		}
	}
	nodeNumber := len(ClusterMapInterface)
	clusterMapString := make(map[string]string, nodeNumber)

	clusterName := make([]string, nodeNumber)

	i := 0
	for name, addr := range ClusterMapInterface {
		if addrAsString, ok := addr.(string); ok {
			clusterMapString[name] = addrAsString
			clusterName[i] = name
			i++
		} else {
			panic("cluster in the config file cannot be decoded correctly")
		}
	}

	sort.Strings(clusterName)

	// deal with p2p_listen_port as a string map
	P2pPortMapInterface := viperRead.GetStringMap("peers_p2p_port")
	if nodeNumber != len(P2pPortMapInterface) {
		panic("p2p_listen_port does not match with cluster")
	}
	p2pPortMapInterface:=make(map[string]int)
	mapNameToP2PPort := make(map[string]int, nodeNumber)
	for name, _ := range clusterMapString {
		portAsInterface, ok := P2pPortMapInterface[name]
		if !ok {
			panic("p2p_listen_port does not match with cluster")
		}
		if portAsInt, ok := portAsInterface.(int); ok {
			mapNameToP2PPort[name] = portAsInt
			rs := []rune(name)
			ipIndex,_ := strconv.Atoi(string(rs[4:]))
			for j:=0;j<ProcessCount;j++ {
				if ipIndex==0{
					for k:=0;k<leaderCount;k++{
						subScript:=strconv.Itoa(k)
						p2pPortMapInterface["node"+subScript]=portAsInt+k*10
					}
					break
				}
				subScript:=strconv.Itoa((ipIndex-1)*ProcessCount+j+leaderCount)
				p2pPortMapInterface["node"+subScript]=portAsInt+j*10
			}
		} else {
			panic("p2p_listen_port contains a non-int value")
		}
	}

	// create the ED25519 keys
	privKeysED25519 := make(map[string]string)
	pubKeysED25519 := make(map[string]string)

	var privKeyED, pubKeyED []byte
	for i:=0;i<nodeNumber;i++{
		if i==0{
			for k:=0;k<leaderCount;k++{
				privKeyED, pubKeyED = sign.GenED25519Keys()
				subScript:=strconv.Itoa(k)
				pubKeysED25519["node"+subScript] = hex.EncodeToString(pubKeyED)
				privKeysED25519["node"+subScript] = hex.EncodeToString(privKeyED)
			}
			continue
		}
		for j:=0;j<ProcessCount;j++{

			privKeyED, pubKeyED = sign.GenED25519Keys()
			subScript:=strconv.Itoa((i-1)*ProcessCount+j+leaderCount)
			pubKeysED25519["node"+subScript] = hex.EncodeToString(pubKeyED)
			privKeysED25519["node"+subScript] = hex.EncodeToString(privKeyED)
		}
	}

	// create the threshold signature keys
	TotalNodeNum:=(nodeNumber-1)*ProcessCount+leaderCount
	numT := TotalNodeNum - TotalNodeNum/3
	shares, pubPoly := sign.GenTSKeys(numT, TotalNodeNum)
	expectation := viperRead.GetFloat64("expectation")
	maxPool := viperRead.GetInt("max_pool")
	batchSize := viperRead.GetInt("batch_size")
	rpcListenPort := viperRead.GetInt("rpc_listen_port")
	logLevel := viperRead.GetInt("log_level")
	bgm:=viperRead.GetInt("bgnodes")
	round := viperRead.GetInt("round")
	protocol := viperRead.GetString("protocol")

	evilNode:=generateRandomNumber(1,TotalNodeNum,bgm)
	fmt.Println("EVILNODES",evilNode)

	// write to configure files
	for _, name := range clusterName {
		viperWrite := viper.New()
		var loopCount int
		rs := []rune(name)
		ipIndex, err := strconv.Atoi(string(rs[4:]))
		if err != nil {
			panic("get replicaid failed")
		}
		if ipIndex==0{
			loopCount=leaderCount
		}else{
			loopCount=ProcessCount
		}
		for j:=0;j<loopCount;j++ {

			index:=strconv.Itoa(j)

			var replicaId int

			if ipIndex==0{
				replicaId=j
			}else{
				//计算节点下标
				replicaId=(ipIndex-1)*ProcessCount+j+leaderCount
			}

			viperWrite.SetConfigFile(fmt.Sprintf("%s_%s.yaml", name,index))

			shareAsBytes, err := sign.EncodeTSPartialKey(shares[replicaId])
			if err != nil {
				panic("encode the share")
			}

			tsPubKeyAsBytes, err := sign.EncodeTSPublicKey(pubPoly)
			if err != nil {
				panic("encode the share")
			}
			viperWrite.Set("name", "node"+strconv.Itoa(replicaId))
			viperWrite.Set("address", clusterMapString[name])
			viperWrite.Set("expectation", expectation)
			viperWrite.Set("p2p_listen_port", mapNameToP2PPort[name]+j*10)
			viperWrite.Set("peers_p2p_port", p2pPortMapInterface)
			viperWrite.Set("max_pool", maxPool)
			viperWrite.Set("rpc_listen_port", rpcListenPort+j)
			viperWrite.Set("batch_size", batchSize)
			viperWrite.Set("round", round)
			viperWrite.Set("protocol", protocol)
			viperWrite.Set("PrivKeyED", privKeysED25519["node"+strconv.Itoa(replicaId)])
			viperWrite.Set("cluster_pubkeyed", pubKeysED25519)
			viperWrite.Set("TSShare", hex.EncodeToString(shareAsBytes))
			viperWrite.Set("TSPubKey", hex.EncodeToString(tsPubKeyAsBytes))
			viperWrite.Set("log_level", logLevel)
			viperWrite.Set("cluster_ips", clusterMapInterface)

			if judgeNodeType(replicaId,evilNode){
				viperWrite.Set("nodetype", 1)
			}else {
				viperWrite.Set("nodetype", 0)
			}
			viperWrite.WriteConfig()

		}
	}
}
