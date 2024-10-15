package main

import (
	"io"

	goccyjson "github.com/goccy/go-json"
)

var JSON jsonWrapper

type jsonWrapper struct{}

func (j jsonWrapper) Marshal(v interface{}) ([]byte, error) {
	return goccyjson.Marshal(v)
}

func (j jsonWrapper) Unmarshal(data []byte, v interface{}) error {
	return goccyjson.Unmarshal(data, v)
}

func (j jsonWrapper) NewDecoder(r io.Reader) *goccyjson.Decoder {
	return goccyjson.NewDecoder(r)
}

func (j jsonWrapper) NewEncoder(w io.Writer) *goccyjson.Encoder {
	return goccyjson.NewEncoder(w)
}
