package db

import (
	"encoding/json"
	"path/filepath"
	"sentinel/pkg/bin"

	"go.etcd.io/bbolt"
)

var db *bbolt.DB

func Init(path string) {
	var err error
	db, err = bbolt.Open(filepath.Join(path, "sentinel.db"), 0600, nil)
	if err != nil {
		panic(err)
	}
}

func Write(bucket string, key int, value any) error {
	return db.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(bucket))
		if err != nil {
			return err
		}
		jb, jerr := json.Marshal(value)
		if jerr != nil {
			return jerr
		}
		return b.Put(bin.IntToBytes(key), jb)
	})
}

func ReadRange[T any](bucket string, from, to int, cb func(T)) error {
	return db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		if b == nil {
			return nil
		}

		c := b.Cursor()
		for k, v := c.Seek(bin.IntToBytes(from)); k != nil && bin.BytesToInt(k) <= to; k, v = c.Next() {
			var value T
			if err := json.Unmarshal(v, &value); err != nil {
				return err
			}
			cb(value)
		}
		return nil
	})
}

func DeleteOlderThan(bucket string, timestamp int) error {
	return db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		if b == nil {
			return nil
		}

		c := b.Cursor()
		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			if bin.BytesToInt(k) < timestamp {
				if err := c.Delete(); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

func Close() {
	db.Close()
}

func GetDB() *bbolt.DB {
	return db
}
