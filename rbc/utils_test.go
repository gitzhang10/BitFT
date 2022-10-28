package rbc

import (
	"bytes"
	"testing"
)

func TestDataWithLength(t *testing.T) {
	data := []byte("TestString to be encoded as bytes")
	dataWithLen := encodeDataWithLength(data)

	dataAfterDecode, lenAfterDecode, err := decodeDataWithLength(dataWithLen)
	if err != nil {
		t.Fatal(err)
	}

	if lenAfterDecode != uint64(len(data)) {
		t.Fatal("the lengths before and after decode do not match")
	}

	if !bytes.Equal(data, dataAfterDecode) {
		t.Fatal("the data before and after decode do not match")
	}
}
