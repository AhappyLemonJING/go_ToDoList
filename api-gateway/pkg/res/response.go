package res

import (
	"api-gateway/pkg/e"

	"github.com/gin-gonic/gin"
)

// Response 基础序列化器
type Response struct {
	Status uint        `json:"Status"`
	Data   interface{} `json:"Data"`
	Msg    string      `json:"Msg"`
	Error  string      `json:"Error"`
}

// DataList 带有总数的Data结构
type DataList struct {
	Item  interface{} `json:"Item"`
	Total uint        `json:"Total"`
}

// TokenData 带有token的Data结构
type TokenData struct {
	User  interface{} `json:"User"`
	Token string      `json:"Token"`
}

func ginH(msgCode int, data interface{}) gin.H {
	return gin.H{
		"code": msgCode,
		"msg":  e.GetMsg(uint(msgCode)),
		"data": data,
	}
}
