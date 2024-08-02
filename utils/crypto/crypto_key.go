/*
 * *******************************************************************
 * @项目名称: common
 * @文件名称: crypto_key.go
 * @Date: 2018/08/03
 * @Author: chunhua.guo
 * @Copyright（C）: 2018 BlueHelix Inc.   All rights reserved.
 * 注意：本内容仅限于内部传阅，禁止外泄以及用于其他的商业目的.
 * *******************************************************************
 */

package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"io"
)

// InitRandomKey get random key
func InitRandomKey(keyLen int) ([]byte, error) {
	randomKey := make([]byte, keyLen)
	if _, err := io.ReadFull(rand.Reader, randomKey); err != nil {
		return nil, err
	}
	return randomKey, nil
}

// TransformKey crypto key by randomKey
func TransformKey(key, randomKey []byte) []byte {
	if len(key) != len(randomKey) {
		return nil
	}

	keyLen := len(key)
	copyKey := make([]byte, keyLen)
	copyRandomKey := make([]byte, keyLen)

	for i := 0; i < keyLen; i++ {
		copyRandomKey[i] = randomKey[keyLen-i-1]
	}

	for j := 0; j < keyLen; j++ {
		copyKey[j] = key[j] ^ copyRandomKey[j]
	}

	return copyKey
}

// GetHash20 get password hash method
func GetHash20(content []byte) []byte {
	h := sha256.New()
	h.Write(content)
	bs := h.Sum(nil)
	return bs[len(bs)-20:]
}

func GetSha256(content []byte) []byte {
	h := sha256.Sum256(content)
	return h[:]
}
