# NetCrow

NetCrow 是用 Rust 编写的异地子网共享工具。内网客户端主动连接公网中继，另一网络中的客户端通过本地 SOCKS5 / HTTP 代理访问其共享资源。客户端不需要公网 IP 或入站端口映射，全部业务流量经中继转发，不使用 P2P。

同一个 `netcrow` 可执行文件通过 `client` / `relay` 子命令选择角色，使用 TOML 配置，没有图形界面。源码按模块组织，运行时不需要 Python、Node.js 或额外的应用运行时。

## 能力与边界

- 多客户端发布 IPv4 / IPv6 CIDR 子网，中继维护路由表，按最长前缀匹配转发 TCP 连接。
- 每个客户端使用独立的 ID 和 Token；中继通过 `allowed_subnets` 限制该客户端可以发布的子网。客户端在 `shared_subnets` 中选择实际共享范围，范围必须包含于授权范围内。
- 支持 SOCKS5 `CONNECT`、HTTP `CONNECT` 和普通 HTTP 正向代理。没有匹配的远端子网路由时拒绝请求，不回退到本机直接连接。
- WSS 加密信道，支持预置公钥指纹的自签证书，以及常规 CA 证书链和主机名验证。
- 支持空闲断开、定期上线检查、本地业务请求立即唤醒、心跳保活和断线重连。
- 支持轮询 HTTP(S) 页面并匹配正则，远程停用和恢复隧道。

这是应用层 TCP 代理，不创建 TUN 网卡，不修改系统路由，不提供 DHCP，也不转发 UDP、ICMP、广播或 SOCKS5 `UDP ASSOCIATE`。应用需要显式设置代理或使用 PAC。域名在发起请求的客户端所在网络解析；仅能在公司内部解析的域名，需要本地 DNS 配置或直接使用内网 IP。

WSS 加密业务内容，但网络侧仍可能看到中继 IP、连接时间、流量大小，以及未使用 ECH 时的域名 SNI。TLS 实现也有可识别特征。休眠会减少持续连接，不能保证流量无法识别，也不模拟浏览器 TLS 指纹。中继终止两端 TLS，能够读取转发内容；应用本身使用 HTTPS、SSH 等协议时，其端到端加密仍然有效。已认证客户端应视为同一个互信网络：`allowed_subnets` 是发布权限，不是客户端之间的访问 ACL。

## 编译

安装 Rust stable 工具链后：

```bash
git clone https://github.com/kagamir/NetCrow.git
cd NetCrow
cargo build --release --locked
```

Linux / macOS 产物为 `target/release/netcrow`，Windows 产物为 `target/release/netcrow.exe`。可将对应平台的可执行文件和配置文件复制到目标机器。证书和私钥是持久配置文件，不会编译进二进制。

```bash
cargo test --locked
cargo clippy --all-targets --locked -- -D warnings
cargo fmt --all -- --check
python3 tests/e2e.py target/release/netcrow
```

端到端测试会在本机临时端口启动中继、客户端和测试服务，不需要公网服务器。省略二进制路径时，默认使用 `target/debug/netcrow`；也可通过 `NETCROW_BIN` 环境变量指定。

## 三台机器部署

以下示例使用一台公网中继、一台公司内网电脑和一台家庭电脑。公司电脑能访问 `192.168.1.0/24`，家庭电脑希望访问该网段。

| 机器 | 运行角色 | 配置文件 | 网络要求 |
| --- | --- | --- | --- |
| 公网服务器 | `relay` | `relay.toml` | 接受 TCP 443；也可改为其他端口 |
| 公司电脑 | `client`，发布 `192.168.1.0/24` | `office.toml` | 能向中继发起 WSS；能访问被共享资源 |
| 家庭电脑 | `client`，提供本地代理 | `home.toml` | 能向中继发起 WSS |

端口 443 可能需要系统授予绑定低端口的权限。也可使用 `8443` 等端口，并同步修改客户端 URL 和服务器防火墙规则。

### 1. 配置中继

复制 [examples/relay.toml](examples/relay.toml) 为 `relay.toml`。为 `office` 和 `home` 分别生成不同的随机 Token，例如：

```bash
openssl rand -hex 32
```

将示例中的两个 Token 占位符替换为生成的值。Token 长度必须在 32～256 字节之间，不能直接使用仓库中的示例字符串。把对应 Token 安全分发给各自客户端。

```bash
./netcrow check --mode relay --config relay.toml
./netcrow relay --config relay.toml
```

中继默认在配置文件所在目录生成 `netcrow-cert.pem` 和 `netcrow-key.pem`。两者均不存在时才会生成；两者均存在时复用；只存在其中一个时拒绝启动，以免意外更换身份。Unix 上新生成的私钥文件权限为 `0600`。不要将私钥和含 Token 的配置提交到仓库。

首次启动后，在服务器上另开终端取得公钥指纹：

```bash
./netcrow fingerprint --cert netcrow-cert.pem
```

输出格式为 `sha256/<Base64>`。通过已信任的渠道将该指纹交给客户端；不要仅从待验证的连接中获取并自动信任它。

### 2. 配置公司客户端

复制 [examples/office.toml](examples/office.toml) 为 `office.toml`，修改：

- `relay_url` 为实际中继域名或 IP，例如 `wss://relay.example.com/netcrow`；
- `token` 为中继中 `office` 的 Token；
- `tls.spki_sha256` 为刚获取的公钥指纹；
- `shared_subnets` 为需要共享的子网，同时确认中继授权范围覆盖这些子网。

```bash
./netcrow check --mode client --config office.toml
./netcrow client --config office.toml
```

公司电脑不需要启用 IP 转发或配置 NAT。收到转发请求后，NetCrow 在公司电脑上建立到目标内网地址的 TCP 连接。因此目标服务看到的来源是公司电脑，而不是家庭电脑。

### 3. 配置家庭客户端

复制 [examples/home.toml](examples/home.toml) 为 `home.toml`，填写实际中继 URL、`home` Token 和公钥指纹：

```bash
./netcrow check --mode client --config home.toml
./netcrow client --config home.toml
```

示例监听 `127.0.0.1:1080` 的 SOCKS5 代理及 `127.0.0.1:8080` 的 HTTP 代理。使用内网中实际存在的服务验证：

```bash
curl --socks5-hostname 127.0.0.1:1080 http://192.168.1.20/
curl --proxy http://127.0.0.1:8080 http://192.168.1.20/
curl --proxy http://127.0.0.1:8080 https://192.168.1.20/
```

最后一条命令仍会验证内网 HTTPS 服务自己的证书。服务证书应匹配所访问的域名或 IP，并受 curl 信任。

家庭电脑与公司网络使用相同网段时，显式代理请求仍由 NetCrow 的远端路由选择；不要把不应访问公司的同网段家庭资源也送入代理。

### 4. 仅代理内网，互联网保持直连

NetCrow 只处理应用交给它的请求。浏览器可以使用以下 PAC 配置，将 `192.168.1.0/24` 交给本地 SOCKS5，其余地址直连：

```javascript
function FindProxyForURL(url, host) {
  var ip = dnsResolve(host);
  if (ip && isInNet(ip, "192.168.1.0", "255.255.255.0")) {
    return "SOCKS5 127.0.0.1:1080";
  }
  return "DIRECT";
}
```

此示例适用于支持 `SOCKS5` PAC 指令的浏览器。也可以将匹配项改为 `PROXY 127.0.0.1:8080`。PAC 的 DNS 解析发生在使用它的设备上；内网域名如果无法在家庭网络解析，使用 IP 或配置适当的 DNS。其他应用需按各自代理设置配置，不会自动使用浏览器 PAC。

代理监听默认示例均为回环地址，协议没有额外的代理用户名/密码认证。绑定非回环地址必须显式设置 `allow_remote_proxy = true`；此时所有能访问该端口的主机都可能使用这个客户端的网络权限，应通过网络访问控制限制来源。

## 证书配置

### 自签证书与公钥指纹

```toml
[tls]
spki_sha256 = "sha256/替换为实际的Base64公钥指纹"
```

指纹是证书公钥的 SubjectPublicKeyInfo DER 编码的 SHA-256，不是整个证书的哈希。显式指纹模式以预置公钥作为信任依据，检查证书有效期并验证 TLS 握手签名，不依赖 CA 签名或域名匹配。替换私钥时必须更新客户端指纹；使用同一公钥重签证书不会改变指纹。

### 机构签发证书

中继配置已有 PEM 证书链与私钥：

```toml
[tls]
cert_path = "/etc/netcrow/fullchain.pem"
key_path = "/etc/netcrow/privkey.pem"
```

客户端删除 `tls.spki_sha256`，通过证书覆盖的域名连接。默认信任内置公共根证书，校验证书链、有效期和主机名。中继加载的是本地文件，不负责申请、续期证书；更新文件后重启中继以加载新证书。

使用私有 CA 时，客户端可配置 `ca_cert_path = "company-ca.pem"`，保留常规主机名验证。`ca_cert_path` 与 `spki_sha256` 不能同时设置。配置内的相对证书路径均相对于该配置文件目录。

## 活动、休眠与重连

```toml
[connection]
idle_secs = 600
sleep_secs = 60
probe_secs = 2
heartbeat_secs = 20
heartbeat_timeout_secs = 60
reconnect_secs = 3
open_timeout_secs = 90
connect_timeout_secs = 10
max_streams = 256
```

| 参数 | 默认值 | 含义 |
| --- | ---: | --- |
| `idle_secs` | 600 | 无业务活动多久后断开 WSS；`0` 表示一直保活和断线重连 |
| `sleep_secs` | 60 | 休眠后等待多久再上线检查 |
| `probe_secs` | 2 | 定期上线检查时保留连接的短暂窗口 |
| `heartbeat_secs` | 20 | 连接期间发送心跳的间隔 |
| `heartbeat_timeout_secs` | 60 | 对端长时间无响应时断开并重连；应大于心跳间隔 |
| `reconnect_secs` | 3 | 非休眠断线后的重连间隔基准 |
| `open_timeout_secs` | 90 | 代理请求等待远端建立 TCP 连接的最长时间 |
| `connect_timeout_secs` | 10 | 网络建立连接的超时时间 |
| `max_streams` | 256 | 客户端并发转发连接限制 |

本地代理请求、远端新连接请求和实际业务字节算活动。心跳、路由更新和定期检查不算活动。`idle_secs = 600`、`sleep_secs = 60` 表示 10 分钟无活动后断开，约每分钟上线检查；没有待办业务则再次断开。

- 休眠期间，本机应用发起代理请求会立即唤醒本机客户端。
- 需要访问正在休眠的远端客户端时，中继在限额和超时时间内暂存新连接请求。远端下次上线后接收请求并恢复正常连接状态。
- 中继的 `pending_timeout_secs` 和发起方的 `open_timeout_secs` 应大于远端 `sleep_secs`，并留出 TLS 握手和目标连接时间。示例为 90 秒等待、60 秒休眠。
- 空闲时间达到阈值后，即使有仍打开但无数据的 TCP 会话，也会因 WSS 断开而关闭。恢复连接不会续接或重放原 TCP 会话，应用应自行重试。
- 中继保留已注册客户端的离线路由，便于等待其唤醒。路由表存于内存，中继重启后需要共享方再次注册才能恢复；在此之前请求可能报告无路由。
- 网络恢复和轮询不是严格实时调度，实际等待时间还取决于超时、重连和网络延迟。

各客户端应使用不同 `id`。同时连接的重复 ID 会被拒绝。不同客户端重复发布相同 CIDR 会被拒绝；覆盖范围不同的重叠 CIDR 按最长前缀选择。

## 远程停用与恢复

在需要控制的客户端配置中添加：

```toml
[control]
initially_disabled = false
interval_secs = 60
timeout_secs = 10
max_body_bytes = 1048576

[[control.disable]]
url = "https://control.example.com/netcrow.txt"
regex = '(?m)^office=disabled$'

[[control.enable]]
url = "https://control.example.com/netcrow.txt"
regex = '(?m)^office=enabled$'
```

页面内容变为 `office=disabled` 后，该客户端在条件轮询匹配后停用：断开 WSS，终止现有转发，拒绝新的代理连接。页面内容变为 `office=enabled` 后恢复正常模式。该功能只切换隧道可用状态，不执行网页中的命令，不删除程序或数据。

每组可配置多个规则，组内任一规则匹配即可。停用条件优先于恢复条件：若同轮两者都匹配，保持停用。HTTP 错误、网络错误、非 UTF-8 响应、超过 `max_body_bytes` 等检查失败不会被当作匹配；状态保持不变。任一停用页面检查失败时，本轮也不会根据恢复页面启用，以免绕过尚未确认的停用条件。

程序启动时采用 `initially_disabled`，运行中的状态不会写回配置，也不会跨重启保存。如果需要首次获取页面授权后才连接，可设为 `true` 并配置恢复条件。默认值 `false` 允许程序启动后先尝试连接，再进行条件检查。

条件轮询在休眠和停用期间继续运行，使用独立 HTTP(S) 请求，不走 NetCrow 隧道，也不使用系统代理环境变量。停用不是完全断网，页面访问仍会产生流量。应使用自己控制的 HTTPS 页面；HTTP 页面可被网络中间人篡改。正则采用 Rust `regex` 语法，不支持反向引用或环视。

## 配置和运行说明

- 所有时间参数单位都是秒。除了 `idle_secs`，其他连接间隔和超时必须为正数。
- 未配置 `socks5_listen` / `http_listen` 时，不启动对应代理服务，适合只发布子网的客户端。
- `allowed_subnets = []` 允许客户端连接和访问其他共享网段，但不允许发布网段。
- 客户端和中继都有连接数、消息大小及队列限制。每条 TCP 流使用独立的额度窗口，接收端写入数据后才返还额度；慢速接收会暂停该流的继续读取，避免无限缓冲，并允许其他流继续传输。网络写入超时、协议违规或达到空闲阈值时仍会断开。
- 配置未知字段会导致启动失败，以便尽早发现拼写错误。修改配置后重启相应进程生效。
- `netcrow check` 验证配置；中继模式不会通过该命令生成或加载证书，也不会尝试网络连通性。
- 日志等级通过 `RUST_LOG` 设置，例如 `RUST_LOG=netcrow=debug`。Token 是认证凭据，不应写入公开日志或截图。

## 许可证

[MIT](LICENSE)。
