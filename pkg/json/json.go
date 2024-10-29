package json

import (
	"io"

	goccyjson "github.com/goccy/go-json"
)

func Marshal(v interface{}) ([]byte, error) {
	return goccyjson.Marshal(v)
}

func Unmarshal(data []byte, v interface{}) error {
	return goccyjson.Unmarshal(data, v)
}

func NewDecoder(r io.Reader) *goccyjson.Decoder {
	return goccyjson.NewDecoder(r)
}

func NewEncoder(w io.Writer) *goccyjson.Encoder {
	return goccyjson.NewEncoder(w)
}
