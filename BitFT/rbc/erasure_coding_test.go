package rbc

import (
	"bytes"
	"testing"
)

func TestErasureEncodingAndDecoding(t *testing.T) {
	data := []byte("Data for erasure coding")
	dataLen := len(data)
	numRequired := 10
	numParity := 4

	shards, err := encode(data, numRequired, numParity)
	if err != nil {
		t.Fatal(err)
	}

	// set numParity shards to nil: shards[1], shards[2], shards[3], shards[4]
	for i := 1; i <= numParity; i++ {
		shards[i] = nil
	}
	decodedData, err := decode(shards, numRequired, numParity, dataLen)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decodedData, data) {
		t.Fatal("data decoded is different from the original one")
	}

	// set one more shard to nil: shards[1], shards[2], shards[3], shards[4], shards[5]
	for i := 1; i <= numParity+1; i++ {
		shards[i] = nil
	}
	_, err = decode(shards, numRequired, numParity, dataLen)
	if err == nil {
		t.Fatal("the decoding process should return an error")
	}
}
