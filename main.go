package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/base32"
	"encoding/hex"
	"flag"
	"fmt"
	"golang.org/x/crypto/sha3"
	"log"
	"os"
	"strings"
)

const onionChecksum = ".onion checksum"
const onionTLD = ".onion"
const securePerm = 0600 // equals "rw-------"
const skPrefix = "== ed25519v1-secret: type0 ==\x00\x00\x00"
const version = byte(3)

// b32 converts an arbitrary input to a base32 encoded string
func b32(data []byte) string {
	buf := bytes.NewBuffer(nil)
	encoder := base32.NewEncoder(base32.StdEncoding, buf)
	_, _ = encoder.Write(data)
	return strings.ToLower(buf.String())
}

// hash generates a SHA3-256 hash sum
func hash(data []byte) []byte {
	h := sha3.New256()
	h.Write(data)
	return h.Sum(nil)
}

// checksum generates the checksum as defined within the specification
func checksum(pk ed25519.PublicKey) []byte {
	data := append([]byte{}, onionChecksum...)
	data = append(data, pk...)
	data = append(data, []byte{version}...)
	return hash(data)[:2]
}

// onionAddress derives the onion address from an Ed25519 public key
func onionAddress(pk ed25519.PublicKey) string {
	data := append([]byte{}, pk...)
	data = append(data, checksum(pk)...)
	data = append(data, []byte{version}...)
	return b32(data) + onionTLD
}

// exportSK exports the secret key into a file with secure permissions and a correct prefix
func exportSK(sk ed25519.PrivateKey, file string) error {
	// this function is "Copyright (c) 2018 Chad Retz" and can be found here:
	// https://github.com/cretz/bine/blob/b9d31d9c786616742e39a121b60522e803e96731/torutil/ed25519/ed25519.go#L39
	digest := sha512.Sum512(sk[:32])
	digest[0] &= 248
	digest[31] &= 127
	digest[31] |= 64
	return os.WriteFile(file, append([]byte(skPrefix), digest[:]...), securePerm)
}

// worker brute-forces a key
func worker(prefix string, ch chan ed25519.PrivateKey) {
	for {
		pk, sk, err := ed25519.GenerateKey(nil)
		if err != nil {
			log.Panic(err)
		}

		if onionAddress(pk)[:len(prefix)] == prefix {
			ch <- sk
			return
		}
	}
}

func main() {
	prefix := flag.String("prefix", "", "the prefix of the onion address")
	goroutines := flag.Uint("threads", 8, "the amount of coroutines to use for parallelization")
	output := flag.String("output", "./hs_ed25519_secret_key", "the file to store the secret key in")
	flag.Parse()

	ch := make(chan ed25519.PrivateKey)
	for i := uint(0); i < *goroutines; i++ {
		go worker(*prefix, ch)
	}

	sk := <-ch
	pk := sk.Public().(ed25519.PublicKey)
	fmt.Printf("public key: %s\n", onionAddress(pk))

	err := exportSK(sk, *output)
	if err != nil {
		fmt.Printf("secret key: %s\n", hex.EncodeToString(sk))
		panic(err)
	}
}
