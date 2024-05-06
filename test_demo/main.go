package main

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"

	srp6 "github.com/GoMateoGo/golang-srp6"

	"github.com/gin-gonic/gin"
)

func Verify(userName, pwd string) ([]byte, []byte) {

	// 1. SHA1
	value := fmt.Sprintf("%s:%s", strings.ToUpper(userName), strings.ToUpper(pwd))
	hash := srp6.ToHashSHA([]byte(value))
	// 2. 生成Salt
	salt := srp6.MakeSalt()
	// 3. 转二进制
	nowSalt := srp6.FromBigSalt(salt)
	// 4. 生成Verifier
	verifier := srp6.MakeVerifier(hash[:], nowSalt)
	// 5. 转二进制
	nowVerifier := srp6.FromBigSalt(verifier)
	// 6. 翻转
	srp6.ReverseByteArray(nowVerifier)

	return nowSalt, nowVerifier
}

type Account struct {
	UserName string `json:"username"`
	Password string `json:"password"`
}

func Create(c *gin.Context) {

	start := time.Now() // 获取当前时间

	var account Account
	if err := c.ShouldBindJSON(&account); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	salt, verify := Verify(account.UserName, account.Password)

	//验证结果-结果正确
	verifyResult := srp6.CheckSaltVerifier(account.UserName, account.Password, salt, verify)

	fmt.Println("验证结果:", verifyResult)
	elapsed := time.Since(start) // 计算经过的时间
	data := struct {
		UserName string `json:"username"`
		Password string `json:"password"`
		Result   bool   `json:"result"`
		Time     int64  `json:"time"`
	}{
		UserName: account.UserName,
		Password: account.Password,
		Result:   verifyResult,
		Time:     elapsed.Milliseconds(),
	}

	c.JSON(200, gin.H{
		"Data": data,
	})
	fmt.Println("耗时:", elapsed)
}

func main() {

	//创建测试数据
	//CreateAccounts()

	r := gin.Default()
	g := r.Group("/api")
	g.POST("/test", Create)
	r.Run(":8888")
}

func CreateAccounts() {
	src := rand.NewSource(time.Now().UnixNano())
	rng := rand.New(src)
	accounts := make([]Account, 10000)
	for i := 0; i < 10000; i++ {
		account := Account{
			UserName: randSeq(7, rng),
			Password: randSeq(7, rng),
		}
		accounts[i] = account
	}
	file, _ := json.MarshalIndent(accounts, "", " ")
	_ = os.WriteFile("accounts.json", file, 0644)
}

func randSeq(n int, rng *rand.Rand) string {
	letters := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rng.Intn(len(letters))]
	}
	return string(b)
}
