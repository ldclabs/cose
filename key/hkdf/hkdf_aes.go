// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package hkdf

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"io"
)

// NewAES returns a Reader, from which keys can be read, using the given cipher.Block as AES-CBC-MAC PRF,
// and context info. Context info can be nil.
func NewAES(block cipher.Block, info []byte) io.Reader {
	return &aesHKDF{block: block, info: info, counter: 1}
}

type aesHKDF struct {
	block cipher.Block

	info    []byte
	counter byte

	buf    []byte
	prev   []byte
	output []byte
}

var fixedIV = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

func (f *aesHKDF) Read(p []byte) (int, error) {
	// Check whether enough data can be generated
	need := len(p)
	remains := len(f.output) + int(255-f.counter+1)*aes.BlockSize
	if remains < need {
		return 0, errors.New("cose/go/key/hkdf: HKDF-AES: entropy limit reached")
	}

	// Read any leftover from the buffer
	n := copy(p, f.output)
	p = p[n:]

	// Fill the rest of the buffer
	for len(p) > 0 {
		inputSize := len(f.prev) + len(f.info) + 1
		x := inputSize % aes.BlockSize
		if x > 0 {
			inputSize += aes.BlockSize - x
		}

		if cap(f.buf) < inputSize {
			f.buf = make([]byte, 0, inputSize)
		}

		f.buf = append(f.buf[:0], f.prev...)
		f.buf = append(f.buf, f.info...)
		f.buf = append(f.buf, f.counter)
		f.buf = append(f.buf, fixedIV[:aes.BlockSize-x]...)

		mode := cipher.NewCBCEncrypter(f.block, fixedIV)
		mode.CryptBlocks(f.buf, f.buf)

		// Read digest
		f.prev = append(f.prev[:0], f.buf[len(f.buf)-aes.BlockSize:]...)
		f.counter++

		// Copy the new batch into p
		f.output = f.prev
		n = copy(p, f.output)
		p = p[n:]
	}

	// Save leftovers for next run
	f.output = f.output[n:]
	return need, nil
}
