package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"flag"
	"fmt"
	"github.com/codahale/blake2"
	"github.com/jzelinskie/whirlpool"
	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/sha3"
	"hash"
	"os"
)

/* Argument parsing  */
var b64Flag = flag.Bool("base64", false, "Base64 encode the output")
var sha1Flag = flag.Bool("sha1", false, "Hash with SHA1")
var md5Flag = flag.Bool("md5", false, "Hash with MD5")
var sha256Flag = flag.Bool("sha-256", false, "Hash with SHA256")
var sha384Flag = flag.Bool("sha-385", false, "Hash with SHA384")
var sha512Flag = flag.Bool("sha-512", false, "Hash with SHA512")
var sha3256Flag = flag.Bool("sha3-256", false, "Hash with SHA3-256")
var sha3384Flag = flag.Bool("sha3-384", false, "Hash with SHA3-384")
var sha3512Flag = flag.Bool("sha3-512", false, "Hash with SHA3-512")
var whirlpoolFlag = flag.Bool("whirlpool", false, "Hash with Whirlpool")
var blakeFlag = flag.Bool("blake", false, "Hash with Blake")
var ripemd160Flag = flag.Bool("ripemd160", false, "Hash with RIPEMD-160")

func main() {
	flag.Parse()

	hashAlgorithm := sha1.New()
	if *sha1Flag {
		hashAlgorithm = sha1.New()
	}
	if *md5Flag {
		hashAlgorithm = md5.New()
	}
	if *sha256Flag {
		hashAlgorithm = sha256.New()
	}
	if *sha384Flag {
		hashAlgorithm = sha512.New384()
	}
	if *sha3256Flag {
		hashAlgorithm = sha3.New256()
	}
	if *sha3384Flag {
		hashAlgorithm = sha3.New384()
	}
	if *sha3512Flag {
		hashAlgorithm = sha3.New512()
	}
	if *whirlpoolFlag {
		hashAlgorithm = whirlpool.New()
	}
	if *blakeFlag {
		hashAlgorithm = blake2.NewBlake2B()
	}
	if *ripemd160Flag {
		hashAlgorithm = ripemd160.New()
	}

	for _, fileName := range flag.Args() {
		f, _ := os.Open(fileName)
		defer f.Close()
		hashAlgorithm.Reset()
		output := genericHashFile(f, hashAlgorithm)
		if *b64Flag {
			r64Output := base64.StdEncoding.EncodeToString(output)
			fmt.Printf("%s %s\n", r64Output, fileName)
		} else {
			fmt.Printf("%x %s\n", output, fileName)
		}
	}

}

/**
 * Generic file hash function.
 */
func genericHashFile(file *os.File, hasher hash.Hash) []byte {
	file.Seek(0, 0)

	const BUFFER_SIZE = 1024 * 1024 * 32
	var buffer [BUFFER_SIZE]byte

	for {
		switch nr, err := file.Read(buffer[:]); true {
		case nr < 0:
			fmt.Printf("Error reading file: %s\n", err.Error())
			os.Exit(1)
		case nr == 0:
			// finish the hash
			return hasher.Sum(nil)
		case nr > 0:
			// Hash the file
			hasher.Write(buffer[:nr])
		}
	}
}
