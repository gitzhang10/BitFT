package rbc

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math"
)

// return the ceiling number for a two-power of N
func twoPowerCeil(n int) int {
	return int(math.Pow(2, math.Ceil(math.Log2(float64(n)))))
}

// generate the hash
func genMsgHashSum(data []byte) []byte {
	msgHash := sha256.New()
	_, err := msgHash.Write(data)
	if err != nil {
		panic(err)
	}
	return msgHash.Sum(nil)
}

func convertUint64ToBytes(n uint64) []byte {
	nInbytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(nInbytes, n)
	return nInbytes
}

func dataLengthInBytes(data []byte) []byte {
	length := uint64(len(data)) // data must be smaller than 2^64 bytes (2^24 TB)
	return convertUint64ToBytes(length)
}

// add the length at the head of data
func encodeDataWithLength(data []byte) []byte {
	lengthInBytes := dataLengthInBytes(data)
	return append(lengthInBytes, data...)
}

// decode the data with length
// @return: the original data, length of data
func decodeDataWithLength(dataWithLen []byte) ([]byte, uint64, error) {
	if len(dataWithLen) < 8 {
		return nil, 0, errors.New("datawithlen should be longer than 8 bytes")
	}
	lengthInBytes := dataWithLen[:8]
	data := dataWithLen[8:]
	return data, binary.LittleEndian.Uint64(lengthInBytes), nil
}

// encode encodes the data into bytes.
// Data can be of any type.
// Examples can be seen form the tests.
func encodeBytes(data interface{}) ([]byte, error) {
	buf := bytes.Buffer{}
	enc := json.NewEncoder(&buf)
	if err := enc.Encode(data); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// decode decodes bytes into the data.
// Data should be passed in the format of a pointer to a type.
// Examples can be seen form the tests.
func decodeBytes(s []byte, data interface{}) error {
	dec := json.NewDecoder(bytes.NewReader(s))
	if err := dec.Decode(data); err != nil {
		return err
	}
	return nil
}
