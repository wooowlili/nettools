# lidar 设计文档

## 1. 目标与定位

lidar 是一个 TCP SYN 网络可达性探测工具。通过向目标 IP 发送原始 TCP SYN 报文并分析响应，判定目标主机和端口的网络状态：

| 响应类型 | 含义 |
|----------|------|
| SYN-ACK | 目标端口开放，网络可达 |
| RST | 目标端口关闭/被拒绝，但网络连通 |
| Timeout | 无响应，目标不可达或丢包 |

核心优势：**无需在远端部署任何软件**。利用目标主机内核 TCP 协议栈自动响应 SYN 报文的特性，只需目标 IP 和端口即可探测。

## 2. 整体架构

```
┌─────────────────────────────────────────────────────┐
│                    cmd/lidar/main.go                 │
│  CLI 参数解析 → Config 校验 → Scanner 创建 → 启动   │
└───────────────────────┬─────────────────────────────┘
                        │
┌───────────────────────┴─────────────────────────────┐
│                  lidar/scanner.go (共享)              │
│  ┌───────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │ 发送主循环 │  │ processIPPacket│  │  buildSYN   │  │
│  │  (Run)    │  │  (响应分类)   │  │ (报文构造)   │  │
│  └─────┬─────┘  └──────┬───────┘  └──────────────┘  │
│        │               │                              │
│  startReceiver    processIPPacket                     │
│  fixByteOrder     (平台无关的 IP/TCP 解析)            │
└────────┼───────────────┼─────────────────────────────┘
         │               │
    ┌────┴────┐     ┌────┴────┐
    │ macOS   │     │  Linux  │
    │  BPF    │     │ Raw Socket│
    └─────────┘     └──────────┘
```

### 文件结构

| 文件 | 构建标签 | 职责 |
|------|----------|------|
| `scanner.go` | — | Scanner 结构体、发送主循环、IP/TCP 报文解析、报文构造 |
| `scanner_darwin.go` | `//go:build darwin` | BPF 设备接收（macOS） |
| `scanner_linux.go` | `//go:build linux` | Raw socket + cBPF 过滤接收（Linux） |
| `config.go` | — | 配置结构体、校验、本地 IP 自动检测 |
| `sender.go` | — | 统计输出格式化（LidarSender） |

## 3. 核心流程

### 3.1 发送

1. 打开发送 socket：`AF_INET, SOCK_RAW, IPPROTO_RAW` + `IP_HDRINCL`
2. 通过 goscapy 构造完整的 IP + TCP SYN 报文（包含 IP 头）
3. 平台相关的字节序修正（`fixByteOrder`）
4. `syscall.Sendto` 发送到目标 IP
5. 源端口自动轮转，覆盖多条 ECMP 路径

### 3.2 接收（平台差异）

**macOS — BPF 设备：**

macOS 上 `SOCK_RAW + IPPROTO_TCP` **无法接收 TCP 响应**。原因是内核 TCP 协议栈会优先处理 TCP 报文，raw socket 拿不到副本。因此需要通过 `/dev/bpf*` 设备在链路层抓包：

1. 打开 `/dev/bpf*` 设备
2. 通过 ioctl 绑定到出接口（`BIOCSETIF`）
3. 设置 immediate mode + promiscuous mode
4. 读取 BPF 数据包（包含 BPF 头 + 链路层头 + IP+TCP）
5. 根据数据链路类型（DLT）剥离链路层头后交给 `processIPPacket`

**Linux — Raw Socket + Classic BPF 过滤：**

Linux 上 raw socket 的工作方式不同：内核 TCP 协议栈处理 TCP 报文的同时，会将副本投递到 raw socket。因此可以直接用 `SOCK_RAW + IPPROTO_TCP` 接收。但 raw socket 默认会收到**所有 TCP 报文**，在高吞吐服务器上会造成大量不必要的内核-用户态数据拷贝。

因此 Linux 端使用 `SO_ATTACH_FILTER` 在内核层挂载 classic BPF（cBPF）过滤器，只投递匹配探测端口的报文：

1. 打开接收 socket：`AF_INET, SOCK_RAW, IPPROTO_TCP`
2. 通过 `SO_ATTACH_FILTER` 挂载 cBPF 过滤器（12 条指令）
3. 从 raw socket 读取数据（直接是 IP 包，无链路层头）
4. 交给 `processIPPacket` 处理

BPF 过滤逻辑：

```
A = packet[0] & 0x0f * 4        // 从 IP IHL 字段计算 TCP 头偏移
M[0] = A                         // 保存偏移
A = packet[A+0..1]               // TCP srcPort
if A != serverPort → reject
A = M[0]
A = packet[A+2..3]               // TCP dstPort
if A < localPort → reject
if A >= localPort + count → reject
accept
```

这样在万兆网卡、数十万 pps 的服务器上，内核只会把极少量匹配的报文拷贝到用户态，避免了性能问题。

### 3.3 响应分类（processIPPacket）

平台无关的共享逻辑，从 IP 头开始解析：

1. 校验 IP 版本（IPv4）和头部长度（IHL）
2. 提取 TCP 源端口、目的端口、标志位、ACK 序列号
3. 过滤条件：源端口 == 目标端口，目的端口在源端口范围内
4. 通过 ACK 序列号反推发送序列号，映射到目标索引
5. 分类：SYN-ACK（端口开放）或 RST（端口关闭）

### 3.4 统计输出

复用 `stat` 包的时间桶统计算法，每个目标独立统计。`LidarSender` 格式化输出：

```
[WARN] 21:37:14, [192.168.1.14 -> 74.48.173.243], sent: 10, received: 10 (SYN-ACK: 10, RST: 0), timeout: 0
```

## 4. 关键设计决策

### 4.1 为什么使用 syscall 而非 Go 标准库或 x/net

Go 标准库 `net` 包只提供 TCP/UDP 等高层抽象，**不提供 raw socket 支持**（`SOCK_RAW`）。

`golang.org/x/net/ipv4` 可以通过 `net.ListenPacket("ip4:tcp", "0.0.0.0")` + `ipv4.NewRawConn` 实现原始 TCP 报文的收发。它是对 raw socket 的 Go 友好封装，并非无法胜任。

选择直接使用 syscall 的原因：

1. **macOS BPF 通路已决定了 syscall 路线**：BPF 设备的 open/ioctl 在 `x/net` 中没有封装，macOS 分支不可避免地使用纯 syscall。如果 Linux 端改用 `x/net/ipv4`，两端收发模式完全不同，增加维护复杂度。

2. **报文构造库的匹配**：项目已使用 goscapy 构造完整的 IP+TCP 字节流，直接 `syscall.Sendto` 发出最自然。使用 `ipv4.RawConn.WriteTo` 则需要把字节流拆成 header + payload 两部分，多了一层转换。

3. **收包循环的精确控制**：lidar 需要 `select` + timeout 实现干净的退出机制（通过 `stopCh` 信号通知），`ipv4.RawConn.ReadFrom` 是阻塞接口，不便于非阻塞轮询。

4. **一致的代码风格**：发送端（macOS/Linux 共用）已经是 syscall，接收端保持一致更易于理解和维护。

总结：不是 `x/net/ipv4` 做不到，而是 macOS BPF 通路已经决定了 syscall 的路线，Linux 端保持一致更简洁。

### 4.2 为什么 macOS 需要 BPF 而 Linux 不需要

这是两个操作系统内核对 raw socket 的处理差异：

| | macOS | Linux |
|--|-------|-------|
| `SOCK_RAW + IPPROTO_TCP` 接收 | 内核 TCP 栈拦截，raw socket 拿不到副本 | 内核同时投递副本给 raw socket |
| 解决方案 | BPF 设备在链路层抓包 | raw socket 直接接收 |
| 接收数据格式 | BPF 头 + 链路层头 + IP + TCP | 直接 IP + TCP（无链路层头） |

### 4.3 为什么发送端两个平台共用代码

发送端使用 `SOCK_RAW + IPPROTO_RAW + IP_HDRINCL` 在 macOS 和 Linux 上行为一致——唯一的区别是 `ip_len` 和 `ip_off` 的字节序：

- **macOS**：`IP_HDRINCL` 模式下内核期望这两个字段为主机字节序，而 goscapy 构造的是网络字节序，需要 `fixByteOrder` 交换
- **Linux**：内核期望网络字节序，无需交换，`fixByteOrder` 为空操作

### 4.4 Linux 内核 RST 问题

当 lidar 发送 SYN 并收到 SYN-ACK 时，Linux 内核 TCP 协议栈也会处理这个 SYN-ACK。由于内核不知道这个连接（raw socket 绕过了 TCP 栈），它会自动发送 RST。

这**不影响 lidar 的检测准确性**——lidar 通过 raw socket 在 RST 之前就拿到了 SYN-ACK。但 RST 报文可能触发目标主机的 IDS/防火墙告警。

如需消除此副作用：

```bash
sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -s <local_ip> -j DROP
```

这是 TCP SYN 扫描工具的通用问题，nmap 等工具也采用类似的 iptables 方案。

### 4.5 seq 到目标的映射

发送时每个目标依次递增全局 seq（`atomic.AddUint64`），接收时通过 ACK 号反推：

```
ackNum = sentSeq + 1  →  sentSeq = ackNum - 1
targetIdx = (sentSeq - seqStart - 1) % len(targets)
```

减 1 是因为第一个 SYN 的 seq = seqStart + 1（AddUint64 先加后用），所以映射关系为：

- seq = seqStart + 1 → target 0
- seq = seqStart + 2 → target 1
- ...
- seq = seqStart + N → target N-1
- seq = seqStart + N + 1 → target 0（下一轮）

### 4.6 源端口轮转

每次发送一轮（所有目标各发一个 SYN）后，源端口 +1。当源端口超过 `localPort + localPortCount` 时回绕到起始值。这样可以在多条 ECMP 路径上均匀分布探测报文，提高丢包定位的覆盖面。

## 5. 速率控制

使用 `golang.org/x/time/rate` 令牌桶限速，每秒产生 `rate` 个令牌，每次发送消耗 1 个令牌。令牌桶的 burst 大小为 1，确保发包速率严格受控。

## 6. 优雅退出

1. 监听 `SIGINT`/`SIGTERM`，收到信号后 cancel context
2. 主循环检测 context 取消，关闭 `stopCh` 通知接收 goroutine 退出
3. 等待 `delay` 时间让在途报文到达并完成统计
4. 接收 goroutine 通过 `select` + timeout 轮询检测 `stopCh`
