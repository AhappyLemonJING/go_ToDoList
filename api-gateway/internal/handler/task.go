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

func ListTask(ctx *gin.Context) {
	var taskReq service.TaskRequest
	PanicIfTaskError(ctx.Bind(&taskReq))
	claim, err := util.ParseToken(ctx.GetHeader("Authorization"))
	taskReq.UserID = uint32(claim.UserId)
	// 从gin.key中取出服务实例
	taskService := ctx.Keys["task"].(service.TaskServiceClient)
	taskResp, err := taskService.TaskShow(context.Background(), &taskReq)
	PanicIfTaskError(err)
	r := res.Response{
		Data:   taskResp,
		Status: uint(taskResp.Code),
		Msg:    e.GetMsg(uint(taskResp.Code)),
	}
	ctx.JSON(http.StatusOK, r)
}

func CreateTask(ctx *gin.Context) {
	var taskReq service.TaskRequest
	PanicIfTaskError(ctx.Bind(&taskReq))
	claim, err := util.ParseToken(ctx.GetHeader("Authorization"))
	taskReq.UserID = uint32(claim.UserId)
	// 从gin.key中取出服务实例
	taskService := ctx.Keys["task"].(service.TaskServiceClient)
	taskResp, err := taskService.TaskCreate(context.Background(), &taskReq)
	PanicIfTaskError(err)
	r := res.Response{
		Data:   taskResp,
		Status: uint(taskResp.Code),
		Msg:    e.GetMsg(uint(taskResp.Code)),
	}
	ctx.JSON(http.StatusOK, r)
}

func UpdateTask(ctx *gin.Context) {
	var taskReq service.TaskRequest
	PanicIfTaskError(ctx.Bind(&taskReq))
	claim, err := util.ParseToken(ctx.GetHeader("Authorization"))
	taskReq.UserID = uint32(claim.UserId)
	// 从gin.key中取出服务实例
	taskService := ctx.Keys["task"].(service.TaskServiceClient)
	taskResp, err := taskService.TaskUpdate(context.Background(), &taskReq)
	PanicIfTaskError(err)
	r := res.Response{
		Data:   taskResp,
		Status: uint(taskResp.Code),
		Msg:    e.GetMsg(uint(taskResp.Code)),
	}
	ctx.JSON(http.StatusOK, r)
}

func DeleteTask(ctx *gin.Context) {
	var taskReq service.TaskRequest
	PanicIfTaskError(ctx.Bind(&taskReq))
	claim, err := util.ParseToken(ctx.GetHeader("Authorization"))
	taskReq.UserID = uint32(claim.UserId)
	// 从gin.key中取出服务实例
	taskService := ctx.Keys["task"].(service.TaskServiceClient)
	taskResp, err := taskService.TaskDelete(context.Background(), &taskReq)
	PanicIfTaskError(err)
	r := res.Response{
		Data:   taskResp,
		Status: uint(taskResp.Code),
		Msg:    e.GetMsg(uint(taskResp.Code)),
	}
	ctx.JSON(http.StatusOK, r)
}
