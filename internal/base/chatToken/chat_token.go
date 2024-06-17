package chatToken

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type CustomerInfo struct {
	Platform   string `json:"platform"`
	UserID     string `json:"userId"`
	Username   string `json:"username"`
	Email      string `json:"email"`
	Phone      string `json:"phone"`
	ExtendInfo string `json:"extendInfo"`
}

func GenerateJWT(customerInfo CustomerInfo) (string, error) {
	// 设置过期时间，过期时间不可大于一小时
	botId := "f6aeb607-d776-4895-8b01-d598b49958c6"
	botSecret := "HQBF-Hcseg0wEYQiHBSikR0HU8t-VWs7a1i9lmdCMT8"
	expires := time.Now().Add(time.Hour).Unix()
	messageToSign := fmt.Sprintf("%s:%d", botId, expires)
	h := hmac.New(sha256.New, []byte(botSecret))
	h.Write([]byte(messageToSign))
	signature := fmt.Sprintf("%s:%d", hex.EncodeToString(h.Sum(nil)), expires)

	headers := jwt.MapClaims{
		"alg": "HS256",
		"typ": "JWT",
	}

	payload := jwt.MapClaims{
		"customer":  customerInfo,
		"signature": signature,
		"iat":       time.Now().Unix(),
		"aud":       "qm:bot",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, payload)
	token.Header = headers

	jwtToken, err := token.SignedString([]byte(botSecret))
	if err != nil {
		return "", err
	}

	return jwtToken, nil
}
