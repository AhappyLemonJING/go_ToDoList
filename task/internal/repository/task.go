package repository

import (
	"errors"
	"task/internal/service"
)

type Task struct {
	TaskID    uint `gorm:"primarykey"`
	UserID    uint `gorm:"index"`
	Status    int  `gorm:"default:0"`
	Title     string
	Content   string `gorm:"type:longtext"`
	StartTime int64
	EndTime   int64
}

func (task *Task) TableName() string {
	return "task"
}

func (task *Task) TaskCreate(req *service.TaskRequest) error {
	task = &Task{
		UserID:    uint(req.UserID),
		Title:     req.Title,
		Content:   req.Content,
		StartTime: int64(req.StartTime),
		EndTime:   int64(req.EndTime),
	}
	return DB.Create(task).Error
}

func (task *Task) TaskDelete(req *service.TaskRequest) error {
	err := DB.Model(&Task{}).Where("task_id=?", req.TaskID).Delete(&task).Error
	return err
}

func (task *Task) TaskUpdate(req *service.TaskRequest) error {
	err := DB.Model(&Task{}).Where("task_id=?", req.TaskID).First(&task).Error
	if err != nil {
		return errors.New("task不存在")
	}
	task.Status = int(req.Status)
	task.Title = req.Title
	task.Content = req.Content
	task.StartTime = int64(req.StartTime)
	task.EndTime = int64(req.EndTime)

	return DB.Save(task).Error
}

func (task *Task) TaskShow(req *service.TaskRequest) (taskList []Task, err error) {
	err = DB.Model(&Task{}).Where("user_id=?", req.UserID).Find(&taskList).Error
	if err != nil {
		return nil, err
	}
	return taskList, nil
}

func BuildTasks(item []Task) (tList []*service.TaskModel) {
	for _, it := range item {
		ut := &service.TaskModel{
			TaskID:    uint32(it.TaskID),
			UserID:    uint32(it.UserID),
			Status:    uint32(it.Status),
			Title:     it.Title,
			Content:   it.Content,
			StartTime: uint32(it.StartTime),
			EndTime:   uint32(it.EndTime),
		}
		tList = append(tList, ut)
	}

	return tList
}
