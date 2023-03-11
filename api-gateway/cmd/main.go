package main

import (
	"api-gateway/config"
	"api-gateway/discovery"
	"api-gateway/internal/service"
	"api-gateway/routers"
	"os"
	"os/signal"
	"syscall"

	"fmt"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"

	"google.golang.org/grpc"
	"google.golang.org/grpc/resolver"
)

func main() {
	// 服务发现
	etcdAddress := []string{config.Conf.GetString("etcd.address")}
	etcdRegister := discovery.NewResolver(etcdAddress, logrus.New())
	resolver.Register(etcdRegister)

	go startListen()
	{
		osSignal := make(chan os.Signal, 1)
		signal.Notify(osSignal, os.Interrupt, os.Kill, syscall.SIGTERM, syscall.SIGINT, syscall.SIGKILL)
		s := <-osSignal
		fmt.Println("exit!", s)
	}
	fmt.Println("gateway listen on 8008")
}

// 监听转载路由
func startListen() {
	opts := []grpc.DialOption{
		grpc.WithInsecure(),
	}
	userConn, _ := grpc.Dial("127.0.0.1:10001", opts...)
	userService := service.NewUserServiceClient(userConn)

	taskConn, _ := grpc.Dial("127.0.0.1:10002", opts...)
	taskService := service.NewTaskServiceClient(taskConn)

	r := routers.NewRouter(userService, taskService)
	server := &http.Server{
		Addr:           config.Conf.GetString("server.port"),
		Handler:        r,
		ReadTimeout:    time.Second * 10,
		WriteTimeout:   time.Second * 10,
		MaxHeaderBytes: 1 << 20,
	}
	err := server.ListenAndServe()
	if err != nil {
		fmt.Println("绑定失败 端口可能被占用", err)
	}
}
