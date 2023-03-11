package routers

import (
	"api-gateway/internal/handler"
	"api-gateway/middleware"
	"net/http"

	"github.com/gin-gonic/gin"
)

func NewRouter(service ...interface{}) *gin.Engine {
	r := gin.Default()
	r.Use(middleware.Cors(), middleware.InitMiddleware(service))
	v1 := r.Group("/api/v1")
	{
		v1.GET("/ping", func(ctx *gin.Context) {
			ctx.JSON(http.StatusOK, gin.H{
				"message": "pong",
			})
		})
		// 用户服务
		v1.POST("/user/register", handler.UserRegister)
		v1.POST("/user/login", handler.UserLogin)

		authed := v1.Group("/")
		authed.Use(middleware.AuthCheck())
		{
			authed.GET("task", handler.ListTask)
			authed.POST("task", handler.CreateTask)
			authed.PUT("task", handler.UpdateTask)
			authed.DELETE("task", handler.DeleteTask)
		}

	}
	r.Run(":8008")
	return r
}
