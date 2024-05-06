package srp6

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

const (
	N   = "894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7"
	G   = "7"
	Num = 32
)

// 是一个用于计算SHA-1哈希值的方法
func ToHashSHA(value []byte) []byte {
	hash := sha1.New()
	hash.Write(value)
	result := hash.Sum(nil)
	return result
}

// 对负数的大整数执行补码操作
func MakePositive(inValue *big.Int) *big.Int {
	if inValue.Sign() < 0 {
		// 转换为字节数组
		oldBytes := inValue.Bytes()
		newBytes := make([]byte, len(oldBytes)+1)
		copy(newBytes, oldBytes)
		// 在最高位补0
		newBytes[len(oldBytes)] = 0
		return new(big.Int).SetBytes(newBytes)
	}
	return inValue
}

// 将大整数转换为无符号字节数组
func ToUnsignedByteArray(bigInt *big.Int) []byte {
	bigIntByteArray := bigInt.Bytes()

	if len(bigIntByteArray) > 0 && bigIntByteArray[len(bigIntByteArray)-1] == 0 {
		// 创建一个缩短的字节数组
		shortenedByteArray := make([]byte, len(bigIntByteArray)-1)
		for i := 0; i < len(shortenedByteArray); i++ {
			shortenedByteArray[i] = bigIntByteArray[i]
		}
		bigIntByteArray = shortenedByteArray
	}

	return bigIntByteArray
}

// 连接多个字节数组
func Concatenate(arrays ...[]byte) []byte {
	var length int
	for _, arr := range arrays {
		if arr != nil {
			length += len(arr)
		}
	}

	result := make([]byte, length)
	length = 0

	for _, arr := range arrays {
		if arr != nil {
			copy(result[length:], arr)
			length += len(arr)
		}
	}

	return result
}

// 将大整数转换为固定长度的字节数组
func FromBigSalt(value *big.Int) []byte {
	_bytes := value.Bytes()
	if len(_bytes) < Num {
		res := make([]byte, Num)
		copy(res, _bytes)
		return res
	} else if len(_bytes) > Num {
		bts := make([]byte, Num)
		copy(bts, _bytes[:Num])
		return bts
	}
	return _bytes
}

// 将二进制字符串转换为大整数
func CreateBigInteger(text string) *big.Int {
	isEvenLength := len(text)%2 == 0
	length := len(text)/2 + func(isEven bool) int {
		if isEven {
			return 0
		}
		return 1
	}(isEvenLength)

	result := make([]byte, length+1)

	for i := 0; i < length; i++ {
		j := len(text) - i*2 - 1
		ch := '0'
		if j > 0 {
			ch = rune(text[j-1])
		}
		_bytes := GetHexadecimalByte(byte(ch), text[j])
		result[i] = _bytes
	}

	result[length] = 0
	res := new(big.Int).SetBytes(reverseBytes(result))
	return res
}

// 计算两个十六进制字符的字节值
func GetHexadecimalByte(ch1, ch2 byte) byte {
	upperByte, _ := HexadecimalCharToByte(ch1)
	lowByte, _ := HexadecimalCharToByte(ch2)
	upperByte = upperByte << 4
	return upperByte | lowByte
}

// 将十六进制字符转换为字节
func HexadecimalCharToByte(ch byte) (byte, error) {
	switch {
	case '0' <= ch && ch <= '9':
		return ch - '0', nil
	case 'a' <= ch && ch <= 'f':
		return ch - 'a' + 10, nil
	case 'A' <= ch && ch <= 'F':
		return ch - 'A' + 10, nil
	default:
		return 0, errors.New("invalid hexadecimal character")
	}
}

// 检查Salt和Verifier是否匹配
func CheckSaltVerifier(user, pass string, oldSalt, oldVerifier []byte) bool {
	value := fmt.Sprintf("%s:%s", strings.ToUpper(user), strings.ToUpper(pass))
	hash := ToHashSHA([]byte(value))
	//根据老的salt生成新的ver
	newVer := MakeVerifier(hash[:], oldSalt)
	//转2进制
	newVerifier := FromBigSalt(newVer)
	//翻转
	ReverseByteArray(newVerifier)
	//做对比
	return bytes.Equal(oldVerifier, newVerifier)
}

// 将字节数组转换为十六进制字符串
func ToHexString(bytes []byte) string {
	hexString := ""
	for _, b := range bytes {
		hexString += fmt.Sprintf("%02X", b)
	}
	return hexString
}

// 反转字节数组
func ReverseByteArray(bytes []byte) {
	for i, j := 0, len(bytes)-1; i < j; i, j = i+1, j-1 {
		bytes[i], bytes[j] = bytes[j], bytes[i]
	}
}

// 改为小端排序
func reverseBytes(bytes []byte) []byte {
	reversed := make([]byte, len(bytes))
	for i, j := 0, len(bytes)-1; i < len(bytes); i, j = i+1, j-1 {
		reversed[i] = bytes[j]
	}
	return reversed
}

// 创建Verifier
func MakeVerifier(hash, salt []byte) *big.Int {
	accHash := ToHexString(hash)
	btr := CreateBigInteger(accHash)
	bArray := ToUnsignedByteArray(btr)
	//ReverseByteArray(bArray)

	saltBytes := Concatenate(salt, bArray)
	resSaltBytes := ToHashSHA(saltBytes)
	ReverseByteArray(resSaltBytes)

	hs := ToHexString(resSaltBytes)
	saltedIdentityHash := CreateBigInteger(hs)
	generator := CreateBigInteger(G)
	modulus := CreateBigInteger(N)

	verifier := new(big.Int).Exp(generator, saltedIdentityHash, modulus)
	return verifier
}

// 将字节数组转换为大整数
func ToBigInteger(data []byte) *big.Int {
	return new(big.Int).SetBytes(data)
}

func MakeSalt() *big.Int {
	salt := CreateBigIntegerSalt()
	return salt
}

// 生成一个随机的大整数
func CreateBigIntegerSalt() *big.Int {
	randomBytes := make([]byte, Num)
	_, err := rand.Read(randomBytes)
	if err != nil {
		panic(err)
	}
	bigInt := new(big.Int).SetBytes(randomBytes)
	return MakePositive(bigInt)
}
