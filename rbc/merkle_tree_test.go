package rbc

import (
	"bytes"
	"fmt"
	"testing"
)

// Test one element
func TestMerkleTreeBuildingOne(t *testing.T) {
	elems := [][]byte{[]byte("elem1")}
	tree, err := buildMerkleTree(elems)
	if err != nil {
		t.Fatal(err)
	}

	if len(tree) != 2 {
		t.Fatal("number of nodes in the Merkle tree is wrong")
	}

	hash1 := genMsgHashSum(elems[0])
	hash0 := []byte("")

	hashs_mock := [][]byte{hash0, hash1}

	for i, hash := range hashs_mock {
		if !bytes.Equal(tree[i], hash) {
			fmt.Printf("hash %d by mocking: %v\n", i, hash)
			fmt.Printf("hash %d by buildMerkleTree function: %v\n", i, tree[i])
			t.Fatal("merkle tree is built incorrectly")
		}
	}
}

// Test two elements
func TestMerkleTreeBuildingTwo(t *testing.T) {
	elems := [][]byte{[]byte("elem1"), []byte("elem2")}
	tree, err := buildMerkleTree(elems)
	if err != nil {
		t.Fatal(err)
	}

	if len(tree) != 4 {
		t.Fatal("number of nodes in the Merkle tree is wrong")
	}

	hash2 := genMsgHashSum(elems[0])
	hash3 := genMsgHashSum(elems[1])
	hash1 := genMsgHashSum(append(hash2, hash3...))
	hash0 := []byte("")

	hashs_mock := [][]byte{hash0, hash1, hash2, hash3}

	for i, hash := range hashs_mock {
		if !bytes.Equal(tree[i], hash) {
			fmt.Printf("hash %d by mocking: %v\n", i, hash)
			fmt.Printf("hash %d by buildMerkleTree function: %v\n", i, tree[i])
			t.Fatal("merkle tree is built incorrectly")
		}
	}
}

// Test three elements
func TestMerkleTreeBuildingThree(t *testing.T) {
	elems := [][]byte{[]byte("elem1"), []byte("elem2"), []byte("elem3")}
	tree, err := buildMerkleTree(elems)
	if err != nil {
		t.Fatal(err)
	}

	if len(tree) != 8 {
		t.Fatal("number of nodes in the Merkle tree is wrong")
	}

	hash4 := genMsgHashSum(elems[0])
	hash5 := genMsgHashSum(elems[1])
	hash6 := genMsgHashSum(elems[2])
	hash7 := []byte("")
	hash3 := genMsgHashSum(append(hash6, hash7...))
	hash2 := genMsgHashSum(append(hash4, hash5...))
	hash1 := genMsgHashSum(append(hash2, hash3...))
	hash0 := []byte("")

	hashs_mock := [][]byte{hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7}

	for i, hash := range hashs_mock {
		if !bytes.Equal(tree[i], hash) {
			fmt.Printf("hash %d by mocking: %v\n", i, hash)
			fmt.Printf("hash %d by buildMerkleTree function: %v\n", i, tree[i])
			t.Fatal("merkle tree is built incorrectly")
		}
	}
}

// Test four elements
func TestMerkleTreeBuildingFour(t *testing.T) {
	elems := [][]byte{[]byte("elem1"), []byte("elem2"), []byte("elem3"), []byte("elem4")}
	tree, err := buildMerkleTree(elems)
	if err != nil {
		t.Fatal(err)
	}

	if len(tree) != 8 {
		t.Fatal("number of nodes in the Merkle tree is wrong")
	}

	hash4 := genMsgHashSum(elems[0])
	hash5 := genMsgHashSum(elems[1])
	hash6 := genMsgHashSum(elems[2])
	hash7 := genMsgHashSum(elems[3])
	hash3 := genMsgHashSum(append(hash6, hash7...))
	hash2 := genMsgHashSum(append(hash4, hash5...))
	hash1 := genMsgHashSum(append(hash2, hash3...))
	hash0 := []byte("")

	hashs_mock := [][]byte{hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7}

	for i, hash := range hashs_mock {
		if !bytes.Equal(tree[i], hash) {
			fmt.Printf("hash %d by mocking: %v\n", i, hash)
			fmt.Printf("hash %d by buildMerkleTree function: %v\n", i, tree[i])
			t.Fatal("merkle tree is built incorrectly")
		}
	}
}

/*
Merkle tree example of three elements:
             tree[1]
			/       \
       tree[2]      tree[3]
        /    \       /    \
	tree[4] tree[5] tree[6] tree[7]
	  ^		   ^		^		^
    elem1    elem2   elem3
*/
func TestGetMerkleBranch(t *testing.T) {
	elems := [][]byte{[]byte("elem1"), []byte("elem2"), []byte("elem3")}
	hash4 := genMsgHashSum(elems[0])
	hash5 := genMsgHashSum(elems[1])
	hash6 := genMsgHashSum(elems[2])
	hash7 := []byte("")
	hash3 := genMsgHashSum(append(hash6, hash7...))
	hash2 := genMsgHashSum(append(hash4, hash5...))
	//hash1 := genMsgHashSum(append(hash2, hash3...))
	//hash0 := []byte("")

	tree, err := buildMerkleTree(elems)
	if err != nil {
		t.Fatal(err)
	}

	//Test branch for elem1
	branch1_mock := [][]byte{hash4, hash5, hash3}
	branch1, err := getMerkleBranch(tree, 0)
	if err != nil {

	}
	for i, hash := range branch1_mock {
		if !bytes.Equal(hash, branch1[i]) {
			t.Fatal("test branch for elem1")
		}
	}

	//Test branch for elem2
	branch2_mock := [][]byte{hash5, hash4, hash3}
	branch2, err := getMerkleBranch(tree, 1)
	if err != nil {

	}
	for i, hash := range branch2_mock {
		if !bytes.Equal(hash, branch2[i]) {
			t.Fatal("test branch for elem2")
		}
	}

	//Test branch for elem3
	branch3_mock := [][]byte{hash6, hash7, hash2}
	branch3, err := getMerkleBranch(tree, 2)
	if err != nil {

	}
	for i, hash := range branch3_mock {
		if !bytes.Equal(hash, branch3[i]) {
			t.Fatal("test branch for elem3")
		}
	}
}

func TestMerkleBranchVerify(t *testing.T) {
	elems := [][]byte{[]byte("elem1"), []byte("elem2"), []byte("elem3")}
	tree, err := buildMerkleTree(elems)
	if err != nil {
		t.Fatal(err)
	}

	branch, err := getMerkleBranch(tree, 1)

	if len(branch) != 3 {
		t.Fatal("length of branch is wrong")
	}

	ok, err := merkleBranchVerify(branch, tree[1], 1)
	if !ok || err != nil {
		t.Fatal("fail to verify merkle branch")
	}
}
