package main

import (
	"net"
	"user/config"
	"user/discovery"
	"user/internal/handler"
	"user/internal/repository"
	"user/internal/service"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

func main() {
	repository.InitDB()
	// etcd地址
	etcdAddress := []string{config.Conf.GetString("etcd.address")}
	// 服务注册
	etcdRegister := discovery.NewRegister(etcdAddress, logrus.New())
	grpcAddress := config.Conf.GetString("server.grpcAddress")
	userNode := discovery.Server{
		Name: config.Conf.GetString("server.domain"),
		Addr: grpcAddress,
	}
	server := grpc.NewServer()
	defer server.Stop()
	// 绑定服务
	service.RegisterUserServiceServer(server, handler.NewUserService())
	lis, err := net.Listen("tcp", grpcAddress)
	if err != nil {
		panic(err)
	}
	if _, err := etcdRegister.Register(userNode, 10); err != nil {
		panic(err)
	}
	if err = server.Serve(lis); err != nil {
		panic(err)
	}
}
