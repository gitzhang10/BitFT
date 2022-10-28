package rbc

import (
	"bytes"
	"errors"
)

/* build merkle tree from a list of `N` elements:
	@return: a list of `2*TwoPowerCeil(N)` hashes
	The root hash is at tree[1], while tree[0] is always blank
   Example as follows (three elements):
				tree[1]
			   /       \
          tree[2]      tree[3]
           /    \       /    \
     tree[4] tree[5] tree[6] tree[7]
		^		^		^		^
      elem1    elem2   elem3
*/
func buildMerkleTree(elems [][]byte) ([][]byte, error) {
	elemNum := len(elems)
	if elemNum <= 0 {
		return nil, errors.New("there should be at least one element")
	}
	bottomRow := twoPowerCeil(elemNum)
	treeHashes := make([][]byte, bottomRow*2)
	// initialize the merkle tree
	for i, _ := range treeHashes {
		treeHashes[i] = []byte("")
	}
	for i := 0; i < elemNum; i++ {
		treeHashes[bottomRow+i] = genMsgHashSum(elems[i])
	}
	for i := bottomRow - 1; i > 0; i-- {
		buf := bytes.NewBuffer(treeHashes[i*2])
		_, err := buf.Write(treeHashes[i*2+1])
		if err != nil {
			return nil, err
		}
		treeHashes[i] = genMsgHashSum(buf.Bytes())
	}
	return treeHashes, nil
}

// check if n is a power of 2
// if true, return the exponent
func checkTwoPower(n int) (bool, int) {
	exp := 0
	for n > 1 {
		if n%2 != 0 {
			return false, -1
		}
		n = n / 2
		exp++
	}
	return true, exp
}

// get the merkle branch of the index-th element
// a branch includes the hashes of two leaves, sibling node, excluding the root node
func getMerkleBranch(tree [][]byte, index int) ([][]byte, error) {
	ok, exp := checkTwoPower(len(tree))
	if !ok {
		return nil, errors.New("the tree is a wrong format")
	}
	branch := make([][]byte, exp)
	t := index + (len(tree) >> 1)
	branch[0] = tree[t]
	for i := 1; i <= exp; i++ {
		branch[i] = tree[t^1]
		t = t / 2
		if t <= 1 {
			break
		}
	}
	return branch, nil
}

// calculate the root from a merkle branch
func rootFromMerkleBranch(branch [][]byte, index int) ([]byte, error) {
	if len(branch) == 0 {
		return nil, errors.New("branch is empty")
	}
	if len(branch) == 1 {
		return branch[0], nil
	}
	hashComp := branch[0]
	var bytesForHash []byte
	for i := 1; i < len(branch); i++ {
		if index&1 == 0 {
			bytesForHash = append(hashComp, branch[i]...)
		} else {
			bytesForHash = append(branch[i], hashComp...)
		}
		hashComp = genMsgHashSum(bytesForHash)
		index = index >> 1
	}
	return hashComp, nil
}

// verify if the merkle branch is correct against the root hash
func merkleBranchVerify(branch [][]byte, rootHash []byte, index int) (bool, error) {
	hashComp, err := rootFromMerkleBranch(branch, index)
	if err != nil {
		return false, err
	}
	return bytes.Equal(hashComp, rootHash), nil
}
