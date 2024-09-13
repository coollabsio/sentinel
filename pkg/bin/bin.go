package bin

import "encoding/binary"

func IntToBytes(n int) []byte {
	endian := binary.BigEndian
	bytes := make([]byte, 8)
	endian.PutUint64(bytes, uint64(n))
	return bytes
}

func BytesToInt(bytes []byte) int {
	endian := binary.BigEndian
	return int(endian.Uint64(bytes))
}
