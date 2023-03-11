package repository

import (
	"errors"
	"user/internal/service"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type User struct {
	UserId         uint   `gorm:"primarykey"`
	UserName       string `gorm:"unique"`
	NickName       string
	PasswordDigest string
}

func (user *User) TableName() string {
	return "user"
}

const (
	PasswordCost = 12
)

// 获取用户信息
func (user *User) ShowUserInfo(req *service.UserRequest) error {
	if exist := user.CheckUserExist(req); !exist {
		return errors.New("username not exist")
	}
	if !user.CheckPassword(req.Password) {
		return errors.New("密码错误")
	}
	return nil
}

// 判断用户是否存在
func (user *User) CheckUserExist(req *service.UserRequest) bool {
	if err := DB.Where("user_name=?", req.UserName).First(&user).Error; err == gorm.ErrRecordNotFound {
		return false
	}
	return true
}

// 创建用户
func (*User) UserCreate(req *service.UserRequest) (user User, err error) {
	var count int64
	DB.Where("user_name=?", req.UserName).Count(&count)
	if count != 0 {
		return User{}, errors.New("username exist")
	}
	user = User{
		UserName: req.UserName,
		NickName: req.NickName,
	}
	_ = user.SetPassword(req.Password)
	err = DB.Create(&user).Error
	return user, err
}
func (user *User) SetPassword(password string) error {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), PasswordCost)
	if err != nil {
		return err
	}
	user.PasswordDigest = string(bytes)
	return nil
}

func (user *User) CheckPassword(password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(user.PasswordDigest), []byte(password))
	return err == nil
}

func BuildUser(item User) *service.UserModel {
	userModel := service.UserModel{
		UserID:   uint32(item.UserId),
		UserName: item.UserName,
		NickName: item.NickName,
	}
	return &userModel
}
