package handler

import (
	"api-gateway/internal/service"
	"api-gateway/pkg/e"
	"api-gateway/pkg/res"
	"api-gateway/pkg/util"
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
)

func UserRegister(ctx *gin.Context) {
	var userReq service.UserRequest
	PanicIfUserError(ctx.Bind(&userReq))
	// 从gin.key中取出服务实例
	userService := ctx.Keys["user"].(service.UserServiceClient)
	userResp, err := userService.UserRegister(context.Background(), &userReq)
	PanicIfUserError(err)
	r := res.Response{
		Data:   userResp,
		Status: uint(userResp.Code),
		Msg:    e.GetMsg(uint(userResp.Code)),
		//Error:  err.Error(),
	}
	ctx.JSON(http.StatusOK, r)

}

func UserLogin(ctx *gin.Context) {
	var userReq service.UserRequest
	PanicIfUserError(ctx.Bind(&userReq))
	// 从gin.key中取出服务实例
	userService := ctx.Keys["user"].(service.UserServiceClient)
	userResp, err := userService.UserLogin(context.Background(), &userReq)
	PanicIfUserError(err)
	token, err := util.GenerateToken(uint(userResp.UserDetail.UserID))
	r := res.Response{
		Data: res.TokenData{
			User:  userResp.UserDetail,
			Token: token,
		},
		Status: uint(userResp.Code),
		Msg:    e.GetMsg(uint(userResp.Code)),
	}
	ctx.JSON(http.StatusOK, r)

}
