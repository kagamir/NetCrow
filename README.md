# NetCrow

Rust 编写的异地子网共享工具，一个无图形界面的可执行文件，通过 `relay` / `client` 子命令选择角色，使用 TOML 配置。内网客户端主动连接公网中继，无需公网 IP 或端口映射。共享子网的流量经 WSS 中继转发，不使用 P2P；其余目的地址可由客户端直接连接。

## 快速开始

可从 [GitHub Releases](https://github.com/kagamir/NetCrow/releases) 下载对应平台的压缩包，解压后使用其中的可执行文件和 `examples/` 配置。也可以安装 Rust stable 后编译，Linux / macOS 产物为 `target/release/netcrow`，Windows 为 `target/release/netcrow.exe`：

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

1. 为每个客户端设置独立 Token（可用 `openssl rand -hex 32` 生成），替换客户端和中继 `[[peers]]` 中对应的占位符。双方填写相同的原始字符串，程序自动计算 SHA-256 用于认证。
2. 在公网服务器运行 `./netcrow relay --config relay.toml`。默认自动生成并保存自签证书和私钥；以后启动复用。只存在其中一个文件时拒绝启动。443 需要相应绑定权限，也可改用 8443 并同步修改客户端 URL。
3. 另开终端运行 `./netcrow fingerprint --cert netcrow-cert.pem`，通过可信渠道把输出填入两个客户端的 `tls.spki_sha256`，并修改 `relay_url` 为实际中继地址。
4. 公司电脑运行 `./netcrow client --config office.toml`；家庭电脑运行 `./netcrow client --config home.toml`。

应用设置本地代理后即可访问，例如：

```bash
curl --socks5-hostname 127.0.0.1:1080 http://192.168.1.20/
curl --proxy http://127.0.0.1:8080 http://192.168.1.20/
```

启动前可用 `./netcrow check --mode client --config home.toml` 检查配置；中继使用 `--mode relay`。修改配置后重启生效。未配置对应监听地址时，不启动该代理服务。

### Ubuntu systemd 服务

根目录提供 [netcrow-client.service](netcrow-client.service) 和 [netcrow-relay.service](netcrow-relay.service)，打包时也会包含在 Linux 发布包中。二进制固定为 `/usr/local/bin/netcrow`，配置分别为 `/etc/netcrow/client.toml` 和 `/etc/netcrow/relay.toml`，使用独立的 `netcrow` 系统账号运行。

以下以客户端为例，在源码目录或解压后的 Linux 发布目录执行；源码构建时把 `./netcrow` 换成 `target/release/netcrow`。账号仅需创建一次：

```bash
sudo useradd --system --user-group --home-dir /var/lib/netcrow --shell /usr/sbin/nologin netcrow
sudo install -m 0755 ./netcrow /usr/local/bin/netcrow
sudo install -d -m 0750 -o root -g netcrow /etc/netcrow
sudo install -m 0640 -o root -g netcrow examples/home.toml /etc/netcrow/client.toml
sudoedit /etc/netcrow/client.toml
sudo install -m 0644 netcrow-client.service netcrow-relay.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now netcrow-client.service
```

共享子网的客户端可改用 `examples/office.toml`。中继改为复制 `examples/relay.toml` 到 `/etc/netcrow/relay.toml`，编辑 ID、Token 等配置，并将已有 `[tls]` 表中的两个路径改为服务可写的数据目录：

```toml
cert_path = "/var/lib/netcrow/netcrow-cert.pem"
key_path = "/var/lib/netcrow/netcrow-key.pem"
```

然后启用 `netcrow-relay.service`。`/var/lib/netcrow` 由 systemd 自动创建；中继具有绑定 443 等低端口的权限，首次启动会生成证书，用 `sudo /usr/local/bin/netcrow fingerprint --cert /var/lib/netcrow/netcrow-cert.pem` 查看指纹。使用已有证书时，文件须允许 `netcrow` 账号读取。服务会在异常退出后重启；修改配置后运行 `sudo systemctl restart netcrow-client.service`（中继替换服务名），用 `journalctl -u netcrow-client.service -f` 查看日志。

### Docker

打 Git tag 后，CI 会将经过测试的 Linux 静态二进制构建成 `linux/amd64`、`linux/arm64` 多架构镜像，发布到 `ghcr.io/kagamir/netcrow`，仅更新对应 Git tag 和 `latest`，例如 `:v0.2.0` 与 `:latest`。分支和 PR 只构建验证，不推送。Git tag 须符合 Docker 标签格式：1～128 个 ASCII 字母、数字、`_`、`.`、`-`，首字符不能是 `.` 或 `-`。

将已修改的中继配置放在宿主机 `config/relay.toml`，保持其中证书路径为相对路径，以便证书与配置一起持久化：

```bash
docker run -d --name netcrow-relay --restart unless-stopped \
  -p 443:443 -v "$PWD/config:/etc/netcrow" \
  ghcr.io/kagamir/netcrow:latest relay --config /etc/netcrow/relay.toml
docker exec netcrow-relay /netcrow fingerprint --cert /etc/netcrow/netcrow-cert.pem
```

Linux 客户端可用 `--network host`，将配置目录同样挂载到 `/etc/netcrow`，命令改为 `client --config /etc/netcrow/client.toml`。桥接网络下需在客户端配置中监听 `0.0.0.0`、设置 `allow_remote_proxy = true`，再用 `-p 127.0.0.1:1080:1080` 等选项将代理端口发布到宿主机回环地址。

在源码目录中本地构建时，复用 Linux 发布压缩包：把两种架构的 `.tar.gz` 放入 `dist/`，执行 `python3 scripts/prepare-docker.py --archives dist --output docker-bin --require-all`，再执行 `docker buildx build --platform linux/amd64,linux/arm64 -t netcrow:local --output type=oci,dest=netcrow-image.tar .`。镜像仅含静态程序，不含 Shell。

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

## 完整配置参考

以下覆盖全部配置项。注释中的“默认”表示省略该项时的值；“必填”没有默认值。所有时间单位为秒，相对证书路径以配置文件目录为准。示例 ID、Token、地址和指纹必须按部署修改；被注释的可选项不会启用。

### 中继 `relay.toml`

```toml
listen = "0.0.0.0:443"        # 必填：监听 IP:端口；443 只是示例，不是默认值
websocket_path = "/netcrow"  # 默认：WSS 路径，须以 / 开头且不含 ?
pending_timeout_secs = 90    # 默认：等待远端建立连接的最长时间
max_streams_per_peer = 256   # 默认：每个客户端并发流上限，范围 1～4096
peer_timeout_secs = 60       # 默认：客户端多久无消息后判定断线

[tls]                       # 整表可省略，使用以下默认值
cert_path = "netcrow-cert.pem" # 默认：PEM 证书链文件
key_path = "netcrow-key.pem"   # 默认：PEM 私钥文件
names = ["localhost"]         # 默认：自动生成自签证书时的名称

# peers 必填，无默认值：配置 1～256 个客户端，每个 ID 唯一。
[[peers]]
id = "office"               # 必填：1～64 个 ASCII 字母、数字、_ 或 -
token = "REPLACE_WITH_RANDOM_OFFICE_TOKEN" # 必填：原始字符串，无长度和字符限制

[[peers]]
id = "home"
token = "REPLACE_WITH_RANDOM_HOME_TOKEN"
```

### 客户端 `client.toml`

```toml
id = "home"                 # 必填：规则同中继 peers.id，且须与中继登记一致
token = "REPLACE_WITH_RANDOM_HOME_TOKEN" # 必填：须与中继登记一致
relay_url = "wss://relay.example.com/netcrow" # 必填：wss URL，不含账号、密码或片段
shared_subnets = []          # 默认：不共享子网；最多 64 个 IPv4 / IPv6 CIDR
# shared_subnets = ["192.168.1.0/24"] # 替换上一行可共享此网段

# proxy_subnets 默认省略：自动使用已学习的远端子网，不等同于 []。
# proxy_subnets = ["192.168.1.0/24"] # 仅列表内目的地址经中继，其余本机直连
# proxy_subnets = []               # 全部本机直连，与上一行二选一
# socks5_listen = "127.0.0.1:1080"  # 默认省略：不启动 SOCKS5；此端口只是示例
# http_listen = "127.0.0.1:8080"    # 默认省略：不启动 HTTP 代理；此端口只是示例
allow_remote_proxy = false   # 默认：禁止代理监听非回环地址

[tls]                       # 整表可省略：使用内置公共 CA，验证证书链和主机名
# spki_sha256 默认省略；自签模式须填真实 SPKI SHA-256 指纹，以下仅为格式示例。
# spki_sha256 = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
# ca_cert_path = "company-ca.pem" # 默认省略；添加私有 CA，仍检查主机名
# spki_sha256 与 ca_cert_path 互斥；两者都省略时使用公共 CA 模式。

[connection]                # 整表可省略，使用以下默认值
idle_secs = 600              # 默认：10 分钟无隧道业务活动后休眠；0 表示一直保活
sleep_secs = 10              # 默认：休眠后等待多久再上线检查
probe_secs = 2               # 默认：检查窗口，无待办业务则再次断开
heartbeat_secs = 20         # 默认：WSS 心跳间隔
heartbeat_timeout_secs = 60 # 默认：多久未收到中继消息后断开，须大于心跳间隔
reconnect_secs = 3           # 默认：非休眠断线重连间隔基准，附少量随机延迟
open_timeout_secs = 90       # 默认：代理连接请求总等待时间
connect_timeout_secs = 10    # 默认：WSS / 目标 TCP 建连及网络写入超时
max_streams = 256            # 默认：客户端并发流上限，范围 1～4096

[control]                   # 默认省略整表：不启用页面条件轮询
initially_disabled = false  # 配置此表时的默认值：启动时允许隧道连接
interval_secs = 60           # 默认：条件轮询间隔
timeout_secs = 10           # 默认：单次页面请求超时
max_body_bytes = 1048576     # 默认：页面响应最多 1 MiB
disable = []                # 默认：无停用规则；任一规则匹配即可停用
enable = []                 # 默认：无恢复规则；任一规则匹配即可恢复

# 配置规则时，先删除上面的 disable = [] / enable = []，再取消以下注释。
# 可重复添加同名数组表来配置多条规则。url 必填；keyword 与 regex 必须且只能设置一个。
# keyword、regex 默认均省略；keyword 不允许空字符串。
# [[control.disable]]
# url = "https://control.example.com/netcrow.txt" # 必填：HTTP(S) URL
# keyword = 'office=disabled'                   # 页面正文包含完整字面量即命中
# regex = '(?m)^office=disabled$'                # 或改用 Rust regex，不能与 keyword 同时配置
# [[control.enable]]
# url = "https://control.example.com/netcrow.txt" # 必填：HTTP(S) URL
# keyword = 'office=enabled'
```

除 `idle_secs` 可为 `0`，其他时间参数、数量和响应大小限制必须为正数。条件 URL 不得包含账号、密码或片段。未知配置字段会报错，避免拼写错误被忽略。

`token` 支持任意 UTF-8 字符串，不限制长度，也允许空字符串；引号、换行等按 TOML 字符串语法转义。解析后的原文直接计算 SHA-256，使用其 64 个小写十六进制字符组成的摘要认证，不裁剪空白、不做 Unicode 归一化，配置中无需预先哈希。此认证方式使用协议版本 2，客户端和中继必须一起升级，旧版本无法互连。

## 连接与休眠

发起中继请求或传输业务字节算活动，心跳、路由更新、定期检查和直连流量不算。本机中继请求立即唤醒本机；远端休眠时，中继暂存新连接请求，等待其下次上线。默认 10 分钟无活动后休眠，每隔约 10 秒上线检查。中继 `pending_timeout_secs` 与发起方 `open_timeout_secs` 应大于远端 `sleep_secs` 并预留连接时间。

休眠、断线或停用会关闭已有隧道 TCP 会话，恢复后不续接或重放，应用需自行重试。中继在内存保留离线路由；中继重启后，共享方重新注册才能恢复路由。

## 远程停用与恢复

按照完整配置中的 `control` 示例，轮询自己控制的 HTTPS 页面。任一停用规则匹配即断开 WSS、关闭隧道会话并停止中继请求；恢复规则匹配后重新连接，停用规则优先。检查失败保持状态，停用页面检查失败时也不会执行恢复。仅控制隧道状态，不执行页面中的命令。

`keyword` 在完整的 UTF-8 响应正文中查找字面量：区分大小写，空格和换行也参与匹配，不解释正则或解析 HTML。例如 `keyword = 'office[1].*'` 仅匹配原样出现的 `office[1].*`；正文可以包含其他内容。需要整页相等、行边界等匹配时继续使用 `regex`。

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
python3 -m unittest discover -s tests -p 'test_release_*.py'
python3 tests/e2e.py target/release/netcrow
```
