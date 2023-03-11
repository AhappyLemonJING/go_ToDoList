# Gin+gRPC+etcd ToDoList

该项目主要分为三个project：

* user：处理用户后台
* task：处理task后台
* api-gateway：前台与后台远程通信的桥梁

我的实验流程是先编写user，再编写api-gateway将用户的登录注册跑通，再编写task后台并在api-gateway上添加相关的通信。

## 前期准备

### 配置文件、解析配置文件、连接数据库

这些操作和我以前的实验类似，基本是拷贝以前的代码的，但是在配置文件中额外增加了server和etcd

```yaml
server:
  domain: user
  version: 1.0
  jwtSecret: wzj
  grpcAddress: "127.0.0.1:10001"

etcd:
  address: 127.0.0.1:2379

# 其他配置与之前的代码一样
```

解析配置文件与连接数据库和我以前的代码一摸一样，这里就不再进行说明。

### proto

安装好proto和etcd：

Protocol Buffer是一种轻便的、高效的**结构化数据存储格式**，相比于JSON、XML等其他结构化数据格式性能和效率大幅提升，Protobuf以二进制存储、占用空间小。Protobuf在**通信协议和数据存储**等领域应用广泛。

Protobuf在 ***.proto***中定义结构化数据，可以通过protoc工具将 **.proto**文件转化为Golang代码，兼容性好，易于使用。

如果消息类型用于远程通信RPC，我们可以在.proto文件中定义RPC服务接口，关键字为 service。

```protobuf
// userModels.proto
// 该部分是用于显示用户详情信息进行返回的，因此字段不包括密码
syntax="proto3";
package pb;
option go_package="/internal/service;service";
message UserModel {
    // @inject_tag: json:"user_id"
    uint32 UserID=1;
    // @inject_tag: json:"user_name"
    string UserName=2;
    // @inject_tag: json:"nick_name"
    string NickName=3;
}


// userService.proto
// 该部分主要用于实现登陆和注册两个功能，登陆需要用到的字段是UserName和Password，注册则四个字段都需要。
syntax="proto3";
package pb;
import "userModels.proto";
option go_package="/internal/service;service";

message UserRequest {
    // @inject_tag: json:"nick_name" form:"nick_name"
    string NickName=1;
    // @inject_tag: json:"user_name" form:"user_name"
    string UserName=2;
    // @inject_tag: json:"password" form:"password"
    string Password=3;
    // @inject_tag: json:"password_confirm" form:"password_confirm"
    string PasswordConfirm=4;
}

message UserDetailResponse {
    UserModel UserDetail=1;
    uint32 Code=2;
}

// 用于远程通信的两个service
// 在handler中定义了UserService的这两个方法明细，稍后会介绍。
service UserService {
    rpc UserLogin(UserRequest) returns(UserDetailResponse);
    rpc UserRegister(UserRequest) returns(UserDetailResponse);
}
```

```shell
# 通过该命令就可以将proto文件自动创建成go文件
protoc -I internal/service/pb internal/service/pb/*.proto --go_out=plugins=grpc:.
```

另外task部分的proto同理，model和service定义如下所示：

```protobuf
// taskModels.proto
syntax="proto3";
package pb;
option go_package="/internal/service;service";

message TaskModel {
    // @inject_tag: json:"favorite_id"
    uint32 TaskID=1;
    // @inject_tag: json:"user_id"
    uint32 UserID=2;
    // @inject_tag: json:"status"
    uint32 Status=3;
    // @inject_tag: json:"title"
    string Title=4;
    // @inject_tag: json:"content"
    string Content=5;
    // @inject_tag: json:"start_time"
    uint32 StartTime=6;
    // @inject_tag: json:"end_time"
    uint32 EndTime=7;
}

// taskService.proto
syntax="proto3";
package pb;
import "taskModels.proto";
option go_package="/internal/service;service";

message TaskRequest{
    uint32 TaskID=1;
    uint32 UserID=2;
    uint32 Status=3;
    string Title=4;
    string Content=5;
    uint32 StartTime=6;
    uint32 EndTime=7;
}

message TasksDetailResponse {
    repeated TaskModel TaskDetail=1;
    uint32 Code=2; 
}

message CommonResponse {
    uint32 Code=1;
    string Msg=2;
    string Data=3;
}
// 用于和api-gateway进行通信
// task 在handler中定义了这四个service方法，
// api-gateway通过该通信可以访问到task的方法
service TaskService {
    rpc TaskCreate(TaskRequest) returns(CommonResponse);
    rpc TaskUpdate(TaskRequest) returns(CommonResponse);
    rpc TaskShow(TaskRequest) returns(TasksDetailResponse);
    rpc TaskDelete(TaskRequest) returns(CommonResponse);
}
```

## 具体实现

### 用户——user

#### **首先是main部分主要分为注册etcd服务和绑定etcd服务**

1. 基于etcd创建一个register注册器

   ```go
   // 注册器的基本字段
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
   ```

2. 获取etcd地址并使用上述注册器注册服务、设置节点信息userNode并创建一个grpc服务

   ```go
   	// etcd地址
   	etcdAddress := []string{config.Conf.GetString("etcd.address")}
   	// 服务注册
   	etcdRegister := discovery.NewRegister(etcdAddress, logrus.New())
   	grpcAddress := config.Conf.GetString("server.grpcAddress")
   	userNode := discovery.Server{
   		Name: config.Conf.GetString("server.domain"),
   		Addr: grpcAddress,
   	} // 用户节点包括该节点的名字与grpc通信地址
   	server := grpc.NewServer() // 创建一个grpc的新server
   	defer server.Stop()
   ```

3. 将本地handler中的UserService（具体实现用户登陆注册的方法）**绑定**到远程服务上

   ```go
   service.RegisterUserServiceServer(server, handler.NewUserService())
   ```

4. 通过tcp监听grpc地址

   ```go
   lis, err := net.Listen("tcp", grpcAddress)
   	if err != nil {
   		panic(err)
   	}
   ```

6. 通过etcd注册器注册userNode

   ```go
   if _, err := etcdRegister.Register(userNode, 10); err != nil {
   		panic(err)
   	}
   
   
   // discovery/register.go
   // 通过etcd注册器注册userNode
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
   	// 进行注册 这里又调用了etcd自带的注册器r.register()
   	if err = r.register(); err != nil {
   		return nil, err
   	}
   	r.closeCh = make(chan struct{})
   	go r.keepAlive()    // 验证节点状态（etcd服务有没有关闭 ）
   	return r.closeCh, nil
   }
   
   // 重写etcd自带的注册器
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
   	// 把服务put到服务注册 调用了上述构建注册path的方法
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
   		// 如果过期也进行注册
   		case <-ticker.C:
   			if r.keepAliveCh == nil {
   				if err := r.register(); err != nil {
   					fmt.Println("register failed error")
   				}
   			}
   		}
   	}
   }
   
   // 注销
   func (r *Register) unregister() error {
   	_, err := r.cli.Delete(context.Background(), BuildRegisterPath(r.srvInfo))
   	return err
   }
   ```

#### 注册登陆的实现

服务注册与绑定之后就可以编写service的登陆注册功能，这里的方法在api-gateway下可以进行调用（通过远程通信grpc）

##### 注册

* 获取从api-gateway输入的req（UserName、NickName、Password、PasswordConfirm）
* 调用` user.UserCreate(req)`创建用户
* 对于密码需要加密 调用了`"golang.org/x/crypto/bcrypt"`包实现的加密，设置了一个加密种子 必须知道加密种子才能做到解码，所以该加密算法优于先前我实验中的md5算法。
* 调用`repository.BuildUser(user)`返回详细的信息给resp，从api-gateway中可以获取这个结果

```go
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
```

```go
// 创建用户
// 先要判断下该用户名在数据库中是否存在，用户名不能重复创建
// 对于密码需要加密 
// 最后保存到数据库中
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
```

```go
func BuildUser(item User) *service.UserModel {
	userModel := service.UserModel{
		UserID:   uint32(item.UserId),
		UserName: item.UserName,
		NickName: item.NickName,
	}
	return &userModel
}
```

##### 登陆

* 获取从api-gateway输入的req（UserName、Password）
* 调用`user.ShowUserInfo(req)`获取用户信息，先要判断用户是否存在、并校验密码，符合标准才可获取
* 再调用`repository.BuildUser(user)`返回信息到api-gateway中

```go
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
```

```go
// 获取用户信息
// 需要判断用户是否存在
// 需要校验密码
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

func (user *User) CheckPassword(password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(user.PasswordDigest), []byte(password))
	return err == nil
}
```

### 备忘录——Task

#### main部分和user一摸一样，分为注册etcd和绑定etcd服务

#### 备忘录增删改查

##### 增加

* 获取到api-gateway中传过来的参数req（Title、Content、StartTime、EndTime）（其他字段会自动获取 TaskID作为主键自动创建 UserID则通过jwt鉴权后自动获取，Status默认为0）
* 调用`task.TaskCreate(req)`在数据库中创建该req
* 返回的是状态码表示创建成功或者失败

```go
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
```

```go
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
```

##### 删除

* 从api-gateway中获取req（taskid）
* 调用` task.TaskDelete(req)`删除task
* 返回状态码到api-gateway

```go
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
```

```go
func (task *Task) TaskDelete(req *service.TaskRequest) error {
	err := DB.Model(&Task{}).Where("task_id=?", req.TaskID).Delete(&task).Error
	return err
}
```

##### 修改

* 从api-gateway中获取req（taskid）
* 调用` task.TaskUpdate(req)`修改task
* 返回状态码到api-gateway

```go
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
```

```go
// 先判断task在不在，存在该task才可以修改，保存新的信息
// 这里严谨点应该判断下req下的该字段是否为空，为空则不修改，但是方便起见这种小实验就没做这个判断了
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
```

##### 查找

* 从api-gateway中获取req（userid）
* 调用` task.TaskShow(req)`根据用户的id展示他的task
* 展示需要返回所有的task表单，调用`BuildTask(tasklist)`进行获取task信息
* 返回状态码到api-gateway

```go
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
```

```go
func (task *Task) TaskShow(req *service.TaskRequest) (taskList []Task, err error) {
	err = DB.Model(&Task{}).Where("user_id=?", req.UserID).Find(&taskList).Error
	if err != nil {
		return nil, err
	}
	return taskList, nil
}
```

```go
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
```

### api-gateway

**这里首先需要将user和task两个项目下的proto文件以及他们生成的文件全部拷贝进来**

#### 这里main实现服务发现

* 通过etcd地址来发现这个同地址的etcd服务
* 通过goroutine监听转载路由`go startListen()`，通过`routers.NewRouter(userService, taskService)`配置路由，然后通过httpServer监听绑定
* 设计通道接受信号

```go
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
```

```go
// 监听转载路由
func startListen() {
	opts := []grpc.DialOption{
		grpc.WithInsecure(),
	}
  // 根据task的grpc地址进行连接并获取userService服务
	userConn, _ := grpc.Dial("127.0.0.1:10001", opts...)
	userService := service.NewUserServiceClient(userConn)
  // 根据task的grpc地址进行连接并获取taskService服务
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
```

路由配置如下：

* 先设置跨域`r.Use(middleware.Cors(), middleware.InitMiddleware(service))`
* task的增删改查需要用户鉴权，通过jwt进行

```go
func NewRouter(service ...interface{}) *gin.Engine {
	r := gin.Default()
	r.Use(middleware.Cors(), middleware.InitMiddleware(service))
	v1 := r.Group("/api/v1")
	{
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
```

```go
// 通过map来存储两个service
func InitMiddleware(service []interface{}) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ctx.Keys = make(map[string]interface{})
		ctx.Keys["user"] = service[0]
		ctx.Keys["task"] = service[1]
		ctx.Next()
	}
}
```

```go
// 跨域请求
func Cors() gin.HandlerFunc {
	return func(c *gin.Context) {
		method := c.Request.Method               //请求方法
		origin := c.Request.Header.Get("Origin") //请求头部
		var headerKeys []string                  // 声明请求头keys
		for k := range c.Request.Header {
			headerKeys = append(headerKeys, k)
		}
		headerStr := strings.Join(headerKeys, ", ")
		if headerStr != "" {
			headerStr = fmt.Sprintf("access-control-allow-origin, access-control-allow-headers, %s", headerStr)
		} else {
			headerStr = "access-control-allow-origin, access-control-allow-headers"
		}
		if origin != "" {
			c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
			c.Header("Access-Control-Allow-Origin", "*")                                       // 这是允许访问所有域
			c.Header("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE,UPDATE") //服务器支持的所有跨域请求的方法,为了避免浏览次请求的多次'预检'请求
			//  header的类型
			c.Header("Access-Control-Allow-Headers", "Authorization, Content-Length, X-CSRF-Token, Token,session,X_Requested_With,Accept, Origin, Host, Connection, Accept-Encoding, Accept-Language,DNT, X-CustomHeader, Keep-Alive, User-Agent, X-Requested-With, If-Modified-Since, Cache-Control, Content-Type, Pragma")
			// 允许跨域设置                                                                                                      可以返回其他子段
			c.Header("Access-Control-Expose-Headers", "Content-Length, Access-Control-Allow-Origin, Access-Control-Allow-Headers,Cache-Control,Content-Language,Content-Type,Expires,Last-Modified,Pragma,FooBar") // 跨域关键设置 让浏览器可以解析
			c.Header("Access-Control-Max-Age", "172800")                                                                                                                                                           // 缓存请求信息 单位为秒
			c.Header("Access-Control-Allow-Credentials", "false")                                                                                                                                                  //  跨域请求是否需要带cookie信息 默认设置为true
			c.Set("content-type", "application/json")                                                                                                                                                              // 设置返回格式是json
		}
		//放行所有OPTIONS方法
		if method == "OPTIONS" {
			c.JSON(http.StatusOK, "Options Request!")
		}
		// 处理请求
		c.Next() //  处理请求
	}
}

```

```go
// jwt鉴权，获取头部的Authorization字段，进行解析
func AuthCheck() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var code int = 200
		token := ctx.GetHeader("Authorization")
		if token == "" {
			code = 404
		} else {
			userCliams, err := util.ParseToken(token)
			if err != nil {
				code = e.ErrorAuthCheckTokenFail
			} else if time.Now().Unix() > userCliams.ExpiresAt {
				code = e.ErrorAuthCheckTokenTimeout
			}
		}
		if code != 200 {
			ctx.JSON(http.StatusOK, gin.H{
				"status": code,
				"msg":    e.GetMsg(uint(code)),
			})
			ctx.Abort()
			return
		}
		ctx.Next()

	}
}

```

```go
// ParseToken 验证用户token
func ParseToken(token string) (*Claims, error) {
	tokenClaims, err := jwt.ParseWithClaims(token, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if tokenClaims != nil {
		if claims, ok := tokenClaims.Claims.(*Claims); ok && tokenClaims.Valid {
			return claims, nil
		}
	}
	return nil, err
}
```

#### /user/register

* 根据`ctx.Keys["user"]`获取对应的服务
* 调用到user project中的UserRegister方法，返回的是用户的详情信息

```go
// 用户登陆的service
func UserRegister(ctx *gin.Context) {
	var userReq service.UserRequest
	PanicIfUserError(ctx.Bind(&userReq))
	// 从gin.key中取出服务实例
	userService := ctx.Keys["user"].(service.UserServiceClient)
	userResp, err := userService.UserRegister(context.Background(), &userReq)
	PanicIfUserError(err)
	r := res.Response{
		Data:   userResp,
		Status: uint(userResp.Code),
		Msg:    e.GetMsg(uint(userResp.Code)),
		//Error:  err.Error(),
	}
	ctx.JSON(http.StatusOK, r)

}
```

#### /user/login

* 根据`ctx.Keys["user"]`获取对应的服务
* 调用到user project中的UserLogin方法，返回的是用户的详情信息
* 通过`util.GenerateToken`生成token，表示用户的登录状态，有了该token就可以操作task的增删改查
* 并将token和用户的详情信息一起返回

```go
func UserLogin(ctx *gin.Context) {
	var userReq service.UserRequest
	PanicIfUserError(ctx.Bind(&userReq))
	// 从gin.key中取出服务实例
	userService := ctx.Keys["user"].(service.UserServiceClient)
	userResp, err := userService.UserLogin(context.Background(), &userReq)
	PanicIfUserError(err)
	token, err := util.GenerateToken(uint(userResp.UserDetail.UserID))
	r := res.Response{
		Data: res.TokenData{
			User:  userResp.UserDetail,
			Token: token,
		},
		Status: uint(userResp.Code),
		Msg:    e.GetMsg(uint(userResp.Code)),
	}
	ctx.JSON(http.StatusOK, r)
}
```

```go
// GenerateToken 签发用户Token
func GenerateToken(userID uint) (string, error) {
	nowTime := time.Now()
	expireTime := nowTime.Add(24 * time.Hour)
	claims := &Claims{
		UserId: userID,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expireTime.Unix(),
			Issuer:    "38384-SearchEngine",
		},
	}
	tokenClaims := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token, err := tokenClaims.SignedString(jwtSecret)
	if err != nil {
		return "", err
	}
	return token, nil
}
```

#### /task  [GET]查

* 需要解析token获取当前登陆用户的id
* 通过`ctx.Keys["task"]`找到taskService
* 调用Task Project中的TaskShow方法进行展示信息

```go
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
```

#### /task  [POST]增

* 需要解析token获取当前登陆用户的id
* 通过`ctx.Keys["task"]`找到taskService
* 调用Task Project中的TaskCreate方法进行增加信息

```go
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
```

#### /task  [PUT]改

* 需要解析token获取当前登陆用户的id
* 通过`ctx.Keys["task"]`找到taskService
* 调用Task Project中的TaskUpdate方法进行修改信息

```go
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
```

#### /task  [DELETE]改

* 需要解析token获取当前登陆用户的id
* 通过`ctx.Keys["task"]`找到taskService
* 调用Task Project中的TaskDELETE方法进行删除信息

```go
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
```

上述service方法都很类似 不做过多说明。