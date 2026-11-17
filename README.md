# NetCrow

Rust 编写的异地子网共享工具，一个无图形界面的可执行文件，通过 `relay` / `client` 子命令选择角色，使用 TOML 配置。内网客户端主动连接公网中继，无需公网 IP 或端口映射。共享子网的流量经 WSS 中继转发，不使用 P2P；其余目的地址可由客户端直接连接。

## 快速开始

安装 Rust stable 后编译，Linux / macOS 产物为 `target/release/netcrow`，Windows 为 `target/release/netcrow.exe`：

```bash
git clone https://github.com/kagamir/NetCrow.git
cd NetCrow
cargo build --release --locked
```

将可执行文件和对应示例配置复制到三台机器：

| 机器 | 配置示例 | 用途 |
| --- | --- | --- |
| 公网服务器 | [relay.toml](examples/relay.toml) | 监听 TCP 443，认证并转发客户端流量 |
| 公司电脑 | [office.toml](examples/office.toml) | 共享 `192.168.1.0/24` |
| 家庭电脑 | [home.toml](examples/home.toml) | 提供 SOCKS5 `127.0.0.1:1080` 和 HTTP `127.0.0.1:8080` 代理 |

1. 为每个客户端生成独立随机 Token（例如 `openssl rand -hex 32`），替换客户端和中继 `[[peers]]` 中对应的占位符。Token 长度为 32～256 字节。
2. 在公网服务器运行 `./netcrow relay --config relay.toml`。默认自动生成并保存自签证书和私钥；以后启动复用。只存在其中一个文件时拒绝启动。443 需要相应绑定权限，也可改用 8443 并同步修改客户端 URL。
3. 另开终端运行 `./netcrow fingerprint --cert netcrow-cert.pem`，通过可信渠道把输出填入两个客户端的 `tls.spki_sha256`，并修改 `relay_url` 为实际中继地址。
4. 公司电脑运行 `./netcrow client --config office.toml`；家庭电脑运行 `./netcrow client --config home.toml`。

应用设置本地代理后即可访问，例如：

```bash
curl --socks5-hostname 127.0.0.1:1080 http://192.168.1.20/
curl --proxy http://127.0.0.1:8080 http://192.168.1.20/
```

启动前可用 `./netcrow check --mode client --config home.toml` 检查配置；中继使用 `--mode relay`。修改配置后重启生效。未配置对应监听地址时，不启动该代理服务。

## 共享与分流

`shared_subnets` 决定**本机向其他客户端共享哪些子网**，由客户端自行配置；中继只需登记客户端 ID 和 Token。目标服务看到的连接来源是共享方电脑，无需开启系统 IP 转发。

顶层 `proxy_subnets` 决定**本机代理收到哪些目的地址时使用中继**，SOCKS5 和 HTTP 共用：

| 配置 | 经过中继 | 本机直接连接 |
| --- | --- | --- |
| 省略 `proxy_subnets` | 已学习的其他客户端共享子网 | 这些子网以外的地址 |
| `proxy_subnets = ["192.168.1.0/24"]` | 指定网段 | 指定网段以外的地址，即使其他客户端共享了它们 |
| `proxy_subnets = []` | 无 | 所有地址 |

已选为中继转发的请求，如果没有远端路由或远端连接失败，会报错，**不会自动改走直连**。默认自动模式首次使用时需先取得路由表，不能在路由未知时猜测为直连。直连请求不唤醒 WSS、不重置隧道活动计时；远程停用隧道后，能够判定为直连的请求仍可使用。

自动模式以最近收到的路由表为准：休眠时新发布的网段、中继重启后尚未重新注册的网段，可能暂按直连处理。需要固定分流范围时，显式配置 `proxy_subnets`。

域名在本机解析后按 IP 分流；公司专有域名需配置可用 DNS 或改用内网 IP。远端路由按最长前缀匹配，相同 CIDR 不能被不同客户端重复发布。家庭和公司网段重叠时，应显式配置分流范围。

## 连接与休眠

客户端配置示例，时间单位为秒：

```toml
[connection]
idle_secs = 600              # 10 分钟无隧道业务活动后断开；0 表示一直保活
sleep_secs = 60              # 休眠后每隔约 1 分钟上线检查
probe_secs = 2               # 检查窗口，无待办业务则再次断开
heartbeat_secs = 20
heartbeat_timeout_secs = 60
reconnect_secs = 3
open_timeout_secs = 90
connect_timeout_secs = 10
max_streams = 256
```

发起中继请求或传输业务字节算活动，心跳、路由更新、定期检查和直连流量不算。本机中继请求立即唤醒本机；远端休眠时，中继暂存新连接请求，等待其下次上线。中继 `pending_timeout_secs` 与发起方 `open_timeout_secs` 应大于远端 `sleep_secs` 并预留连接时间。

休眠、断线或停用会关闭已有隧道 TCP 会话，恢复后不续接或重放，应用需自行重试。中继在内存保留离线路由；中继重启后，共享方重新注册才能恢复路由。

## 远程停用与恢复

在客户端配置中添加规则，轮询自己控制的 HTTPS 页面：

```toml
[control]
initially_disabled = false
interval_secs = 60

[[control.disable]]
url = "https://control.example.com/netcrow.txt"
regex = '(?m)^office=disabled$'

[[control.enable]]
url = "https://control.example.com/netcrow.txt"
regex = '(?m)^office=enabled$'
```

任一停用规则匹配即断开 WSS、关闭隧道会话并停止中继请求；恢复规则匹配后重新连接，停用规则优先。检查失败保持状态，停用页面检查失败时也不会执行恢复。仅控制隧道状态，不执行页面中的命令。

启动状态取自 `initially_disabled`，不跨重启保存。设为 `true` 可等待恢复规则授权后再连接。页面轮询在休眠和停用期间继续，直接访问页面，不走隧道或系统代理环境变量，因此仍产生流量。

## 证书与边界

自签模式使用 `sha256/<Base64>` 格式的 **SPKI 公钥指纹**，检查有效期和 TLS 握手签名；更换私钥需更新指纹。机构签发证书配置中继 `tls.cert_path` / `tls.key_path`，客户端删除 `tls.spki_sha256` 并通过证书覆盖的域名连接。私有 CA 可配置 `tls.ca_cert_path`，不能与指纹同时使用。相对证书路径以配置文件目录为准。

仅支持 TCP：SOCKS5 CONNECT、HTTP CONNECT 和普通 HTTP 正向代理；不提供 TUN、UDP、ICMP 或 DHCP。代理无独立用户名/密码认证，示例仅监听回环地址；非回环监听需显式 `allow_remote_proxy = true` 并限制访问来源。客户端彼此互信，各自可以发布子网，应妥善保管独立 Token。

WSS 加密内容，但中继 IP、时间、流量大小、SNI 和 TLS 特征仍可能被识别。中继能读取隧道内容；应用自身 HTTPS / SSH 等端到端加密仍然有效。不要提交私钥或实际 Token。

## 验证

```bash
cargo test --locked
cargo clippy --all-targets --locked -- -D warnings
cargo fmt --all -- --check
python3 tests/e2e.py target/release/netcrow
```

日志可通过 `RUST_LOG=netcrow=debug` 调整。许可证：[MIT](LICENSE)。
