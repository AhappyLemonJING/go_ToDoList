package discovery

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	clientv3 "go.etcd.io/etcd/client/v3"
	"golang.org/x/net/context"
)

type Register struct {
	EtcdAddrs   []string
	DialTimeout int
	closeCh     chan struct{}
	leasesID    clientv3.LeaseID
	keepAliveCh <-chan *clientv3.LeaseKeepAliveResponse //   心跳检验

	srvInfo Server
	srvTTL  int64
	cli     *clientv3.Client //客户端
	logger  *logrus.Logger
}

// 基于etcd创建一个register注册器
func NewRegister(etcdAddrs []string, logger *logrus.Logger) *Register {
	return &Register{
		EtcdAddrs:   etcdAddrs,
		DialTimeout: 3,
		logger:      logger,
	}
}

// 创建自己的实例
func (r *Register) Register(srvInfo Server, ttl int64) (chan<- struct{}, error) {
	var err error
	if strings.Split(srvInfo.Addr, ":")[0] == "" {
		return nil, errors.New("invalid ip address")
	}

	// 初始化 建立连接 设置需要的信息
	if r.cli, err = clientv3.New(clientv3.Config{
		Endpoints:   r.EtcdAddrs,
		DialTimeout: time.Duration(r.DialTimeout) * time.Second,
	}); err != nil {
		return nil, err
	}
	r.srvInfo = srvInfo
	r.srvTTL = ttl
	// 进行注册
	if err = r.register(); err != nil {
		return nil, err
	}
	r.closeCh = make(chan struct{})
	go r.keepAlive()
	return r.closeCh, nil
}

// 创建etcd自带的实例
func (r *Register) register() error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(r.DialTimeout)*time.Second)
	defer cancel()
	// 申请一个租约
	leaseResp, err := r.cli.Grant(ctx, r.srvTTL)
	if err != nil {
		return err
	}
	r.leasesID = leaseResp.ID
	// 保证节点存活状态
	if r.keepAliveCh, err = r.cli.KeepAlive(context.Background(), r.leasesID); err != nil {
		return err
	}
	data, err := json.Marshal(r.srvInfo)
	if err != nil {
		return err
	}
	// 把服务put到服务注册
	_, err = r.cli.Put(context.Background(), BuildRegisterPath(r.srvInfo), string(data), clientv3.WithLease(r.leasesID))
	return err
}

// 验证节点状态
func (r *Register) keepAlive() {
	ticker := time.NewTicker(time.Duration(r.srvTTL) * time.Second)
	for {
		select {
		// 如果节点关闭了 就注销、废除租约
		case <-r.closeCh:
			if err := r.unregister(); err != nil {
				fmt.Println("unregister failed error")
			}
			if _, err := r.cli.Revoke(context.Background(), r.leasesID); err != nil {
				fmt.Println("revoke failed error")
			}
		// 如果没有节点，就注册
		case res := <-r.keepAliveCh:
			if res == nil {
				if err := r.register(); err != nil {
					fmt.Println("register failed error")
				}
			}
		// 如果超时也进行注册
		case <-ticker.C:
			if r.keepAliveCh == nil {
				if err := r.register(); err != nil {
					fmt.Println("register failed error")
				}
			}
		}
	}
}

func (r *Register) unregister() error {
	_, err := r.cli.Delete(context.Background(), BuildRegisterPath(r.srvInfo))
	return err
}
