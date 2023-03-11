package handler

import (
	"context"
	"task/internal/repository"
	"task/internal/service"
	"task/pkg/e"
)

type TaskService struct {
}

func NewTaskService() *TaskService {
	return &TaskService{}
}

func (*TaskService) TaskCreate(ctx context.Context, req *service.TaskRequest) (resp *service.CommonResponse, err error) {
	var task repository.Task
	resp = new(service.CommonResponse)
	resp.Code = e.Success
	err = task.TaskCreate(req)
	if err != nil {
		resp.Code = e.Error
		resp.Msg = e.GetMsg(e.Error)
		resp.Data = err.Error()
		return resp, err
	}
	resp.Msg = e.GetMsg(uint(resp.Code))
	return resp, nil

}

func (*TaskService) TaskDelete(ctx context.Context, req *service.TaskRequest) (resp *service.CommonResponse, err error) {
	var task repository.Task
	resp = new(service.CommonResponse)
	resp.Code = e.Success
	err = task.TaskDelete(req)
	if err != nil {
		resp.Code = e.Error
		resp.Msg = e.GetMsg(e.Error)
		resp.Data = err.Error()
		return resp, err
	}
	resp.Msg = e.GetMsg(uint(resp.Code))
	return resp, nil
}

func (*TaskService) TaskUpdate(ctx context.Context, req *service.TaskRequest) (resp *service.CommonResponse, err error) {
	var task repository.Task
	resp = new(service.CommonResponse)
	resp.Code = e.Success
	err = task.TaskUpdate(req)
	if err != nil {
		resp.Code = e.Error
		resp.Msg = e.GetMsg(e.Error)
		resp.Data = err.Error()
		return resp, err
	}
	resp.Msg = e.GetMsg(uint(resp.Code))
	return resp, nil
}

func (*TaskService) TaskShow(ctx context.Context, req *service.TaskRequest) (resp *service.TasksDetailResponse, err error) {
	var task repository.Task
	resp = new(service.TasksDetailResponse)
	resp.Code = e.Success
	tasklist, err := task.TaskShow(req)
	if err != nil {
		resp.Code = e.Error
		return resp, err
	}
	resp.TaskDetail = repository.BuildTasks(tasklist)
	return resp, nil

}
