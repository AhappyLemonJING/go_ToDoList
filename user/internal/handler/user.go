package handler

import (
	"context"
	"fmt"
	"user/internal/repository"
	"user/internal/service"
	"user/pkg/e"
)

type UserService struct {
}

func NewUserService() *UserService {
	return &UserService{}
}

func (*UserService) UserLogin(ctx context.Context, req *service.UserRequest) (resp *service.UserDetailResponse, err error) {
	var user repository.User
	resp = new(service.UserDetailResponse)
	resp.Code = e.Success
	err = user.ShowUserInfo(req)
	fmt.Println("usrinfo", user.UserName)
	if err != nil {
		resp.Code = e.Error
		return resp, err
	}
	resp.UserDetail = repository.BuildUser(user)
	return resp, nil

}

func (*UserService) UserRegister(ctx context.Context, req *service.UserRequest) (resp *service.UserDetailResponse, err error) {
	var user repository.User
	resp = new(service.UserDetailResponse)
	resp.Code = e.Success
	user, err = user.UserCreate(req)
	if err != nil {
		resp.Code = e.Error
		return resp, err
	}
	resp.UserDetail = repository.BuildUser(user)
	return resp, nil

}
