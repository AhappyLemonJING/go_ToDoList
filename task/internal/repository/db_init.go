package repository

import (
	"fmt"
	"strings"
	"task/config"
	"time"

	"github.com/gin-gonic/gin"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"gorm.io/gorm/schema"
)

var DB *gorm.DB

func InitDB() {
	host := config.Conf.GetString("mysql.host")
	port := config.Conf.GetString("mysql.port")
	database := config.Conf.GetString("mysql.database")
	username := config.Conf.GetString("mysql.username")
	password := config.Conf.GetString("mysql.password")
	charset := config.Conf.GetString("mysql.charset")
	dsn := strings.Join([]string{username, ":", password, "@tcp(", host, ":", port, ")/", database, "?charset=", charset, "&parseTime=True&loc=Local"}, "")
	fmt.Println(dsn)
	err := Database(dsn)
	if err != nil {
		panic(err)
	}

}

func Database(dsn string) error {
	var ormLogger logger.Interface
	if gin.Mode() == "debug" {
		ormLogger = logger.Default.LogMode(logger.Info)
	} else {
		ormLogger = logger.Default
	}
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{
		Logger: ormLogger,
		NamingStrategy: schema.NamingStrategy{
			SingularTable: true,
		},
	})
	if err != nil {
		return err
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxIdleConns(20)  //设置连接池 空闲
	sqlDB.SetMaxOpenConns(100) //  最大打开数
	sqlDB.SetConnMaxLifetime(time.Second * 30)
	DB = db
	migration() // 迁移 自动生成表单
	return err

}
