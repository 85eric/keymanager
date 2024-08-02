/*
 * *******************************************************************
 * @项目名称: common
 * @文件名称: crypto.go
 * @Date: 2018/05/15
 * @Author: chunhua.guo
 * @Copyright（C）: 2018 BlueHelix Inc.   All rights reserved.
 * 注意：本内容仅限于内部传阅，禁止外泄以及用于其他的商业目的.
 * *******************************************************************
 */

package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
)

// PKCS7Padding pkcs7 padding for aes
func PKCS7Padding(plainText []byte, blockSize int) []byte {
	padding := blockSize - len(plainText)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(plainText, padText...)
}

// PKCS7UnPadding pkcs7 unPadding for aes
func PKCS7UnPadding(cipherText []byte, blockSize int) []byte {
	length := len(cipherText)
	unPadding := int(cipherText[length-1])
	if unPadding > blockSize {
		return nil
	}
	// check padding OK
	for i := 0; i < unPadding; i++ {
		if int(cipherText[length-1-i]) != unPadding {
			return nil
		}
	}
	return cipherText[:(length - unPadding)]
}

// Encrypt :encrypt wrapper for aes
func Encrypt(plainText, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()
	plainText = PKCS7Padding(plainText, blockSize)
	cipherText := make([]byte, aes.BlockSize+len(plainText))

	iv := cipherText[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	blockMode := cipher.NewCBCEncrypter(block, iv)
	blockMode.CryptBlocks(cipherText[aes.BlockSize:], plainText)
	return cipherText, nil
}

// Decrypt :decrypt wrapper for aes
func Decrypt(cipherText, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()
	if len(cipherText) < blockSize {
		return nil, errors.New("invalid cipherText, too short")
	}

	iv := cipherText[:blockSize]
	cipherText = cipherText[blockSize:]
	blockMode := cipher.NewCBCDecrypter(block, iv)

	plainText := make([]byte, len(cipherText))
	blockMode.CryptBlocks(plainText, cipherText)
	plainText = PKCS7UnPadding(plainText, blockSize)
	if plainText == nil {
		return nil, errors.New("decrypt error")
	}
	return plainText, nil
}

// EncryptWithCRC32 encrypt wrapper for aes with crc32 code
func EncryptWithCRC32(plainText, key []byte) ([]byte, error) {
	plainTextWithCrc := PackDataCRC32(plainText)
	return Encrypt(plainTextWithCrc, key)
}

// DecryptWithCRC32 decrypt wrapper for aes and check crc32 code
func DecryptWithCRC32(cipherText, key []byte) ([]byte, error) {
	packedData, err := Decrypt(cipherText, key)
	if err != nil {
		return nil, err
	}

	return UnPackDataCRC32(packedData)
}

// pack data with crc ending
func PackDataCRC32(plainData []byte) []byte {
	ieee := crc32.NewIEEE()
	_, _ = ieee.Write(plainData)
	s := ieee.Sum32()
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, s)

	return append(plainData, b...)
}

// Unpack data with crc ending
func UnPackDataCRC32(packedData []byte) ([]byte, error) {
	dataLen := len(packedData)
	if dataLen < (4 + 1) {
		return nil, errors.New("data len invalid")
	}
	plainData := packedData[:dataLen-4]
	ieee := crc32.NewIEEE()
	_, _ = ieee.Write(plainData)

	s := ieee.Sum32()
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, s)

	if bytes.Equal(b, packedData[dataLen-4:]) {
		return plainData, nil
	} else {
		//fmt.Printf("orig checksum is %x, calc checksum is %x", packedData[dataLen - 4:], b)
		return nil, errors.New("crc32 checksum error")
	}
}
