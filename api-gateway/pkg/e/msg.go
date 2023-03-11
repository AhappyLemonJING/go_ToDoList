package e

var MsgFlags = map[uint]string{
	Success:                    "ok",
	Error:                      "fail",
	InvalidParams:              "请求参数错误",
	ErrorAuthCheckTokenFail:    "token错误",
	ErrorAuthCheckTokenTimeout: "token过期",
}

// GetMsg
func GetMsg(code uint) string {
	msg, ok := MsgFlags[code]
	if ok {
		return msg
	}
	return MsgFlags[Error]
}
