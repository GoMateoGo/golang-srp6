package main

import (
	"fmt"
	"strings"
)

func Verify(userName, pwd string) ([]byte, []byte) {

	// 1. SHA1
	value := fmt.Sprintf("%s:%s", strings.ToUpper(userName), strings.ToUpper(pwd))
	hash := ToHashSHA([]byte(value))
	// 2. 生成Salt
	salt := MakeSalt()
	// 3. 转二进制
	nowSalt := FromBigSalt(salt)
	// 4. 生成Verifier
	verifier := MakeVerifier(hash[:], nowSalt)
	// 5. 转二进制
	nowVerifier := FromBigSalt(verifier)
	// 6. 翻转
	ReverseByteArray(nowVerifier)

	return nowSalt, nowVerifier
}

func main() {
	var userName = "sUser"
	var password = "sPassword"

	var testPwd = "asdfgh" //错误密码

	salt, verify := Verify(userName, password)

	//验证结果-结果正确
	verifyResult := CheckSaltVerifier(userName, password, salt, verify)

	fmt.Println("正确结果:", verifyResult)

	//验证结果-结果错误
	verifyResult = CheckSaltVerifier(userName, testPwd, salt, verify)

	fmt.Println("错误结果:", verifyResult)
}
