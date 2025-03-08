package hdb

import (
	"os"

	"github.com/awnumar/memguard"
)

type HareDB struct {
	sk          memguard.LockedBuffer
	kv_secure   map[string]string
	kv_insecure map[memguard.Enclave]memguard.Enclave
}

func New() HareDB {

	unsafe_sk := os.Getenv("HAREDB_SECRET_KEY")
	use_secure := len(unsafe_sk) > 0

	hdb := HareDB{
		*memguard.NewBuffer(len(unsafe_sk)),
		make(map[string]string),
		make(map[memguard.Enclave]memguard.Enclave),
	}
	hdb.sk.Bytes()
}
