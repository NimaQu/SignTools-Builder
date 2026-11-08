# Linux 签名 builder

让 [SignTools](https://github.com/SignTools/SignTools) 在**纯 Linux** 上完成 IPA 签名和分发，不需要 macOS，也不需要 GitHub Actions 的 mac runner。

签名引擎是 [apple-codesign / rcodesign](https://github.com/indygreg/apple-platform-rs)，也就是 [Impactor](https://github.com/claration/Impactor) 在 Windows/Linux 上签名用的那个 Rust 库（同为 0.29.0）。

## 原理

```
 iPhone/浏览器 ──上传 IPA──▶ SignTools 服务端 ──/trigger──▶ SignTools-Builder ──运行──▶ linux/sign.py
      ▲                          │   ▲                                                    │
      └──── itms-services 安装 ◀──┘   └──── 拉取任务 / 未签名 IPA，tus 回传已签名 IPA ──────┘
```

SignTools-Builder 本身是跨平台 Go 程序，只负责执行签名脚本。绑死 macOS 的是 SignTools-CI 的 `sign.py`，这里的 `linux/sign.py` 是它的 Linux 版。**和服务端的通信协议完全不变**，只把 macOS 工具全部替换掉：

| 原 sign.py (macOS)                         | Linux 版                                         |
| ------------------------------------------ | ------------------------------------------------ |
| `codesign`                                 | `rcodesign sign`（一次递归签完整个 .app，每个 .app/.appex 用各自的 entitlements） |
| `security` 钥匙串导入 p12                   | `cryptography` 读 p12 → 临时 PEM                  |
| `security cms -D` 解析描述文件               | `openssl cms`（失败时直接从 DER 里提取 plist）      |
| `codesign -d --entitlements`               | 内置 Mach-O 代码签名解析                            |
| `plutil`                                   | Python `plistlib`                                 |
| `otool -L` / `install_name_tool` / `insert_dylib`（插件注入） | LIEF                         |
| `perl` 字节替换（ID 修补）                   | Python `bytes.replace`                            |

Impactor 给 apple-codesign 打的两个补丁（给 Mach-O 补可执行权限、允许嵌套 bundle 没有 `CFBundleIdentifier`），在 `sign.py` 里做了预处理绕过，所以直接用 rcodesign 官方发行版。

## 部署（Docker Compose）

```
linux/
├── docker-compose.yml
├── .env                 # BUILDER_KEY=...
├── signer-cfg.yml       # 服务端配置
├── data/profiles/my_ent/
│   ├── cert.p12              # 企业证书（含私钥）
│   ├── cert_pass.txt         # p12 密码（不要有换行）
│   ├── prov.mobileprovision  # 企业描述文件
│   └── name.txt              # 网页上显示的名字
├── data/import/         # 把大 IPA 放这里（rsync / SMB），然后在网页上选择
└── data/work/           # builder 的工作目录，需要约 2 倍最大 IPA 的空间
```

1. `cd linux && cp .env.example .env`，填一个随机的 `BUILDER_KEY`；`signer-cfg.yml` 里的 `builder.selfhosted.key` 改成同一个值。
2. 把证书和描述文件按上面的结构放到 `data/profiles/<任意名字>/`，并执行 `mkdir -p data/import data/work`。
3. 把 `signer-cfg.yml` 的 `server_url` 改成你的**公网 HTTPS 地址**，改掉 `basic_auth` 的密码。
4. `docker compose up -d --build`

### HTTPS（必需）

iOS 的 `itms-services` 一键安装要求有效的 HTTPS 证书。在前面放 Caddy 或 nginx 反代到 `:8080`：

```
sign.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

nginx 的话要透传 `Host` 和 `X-Forwarded-Proto`，并且要能放行大请求：`client_max_body_size 0; proxy_request_buffering off; proxy_read_timeout 3600s;`。如果你在反代上自己加了鉴权，下面这些路径**不能**加：`/apps/*/`、`/jobs`、`/jobs/*`、`/jobs/*/tus/`、`/files/*`。

### 企业证书

第一次安装后，在 iPhone 上进入：设置 → 通用 → VPN 与设备管理 → 信任你的企业开发者。

## 大包（10 GB 以上，例如 nxnative 移植的游戏）

推荐的部署方式是**服务端和 builder 在同一台机器上**（`docker-compose.yml` 默认就是这样），大文件不经过浏览器：

```bash
# 1. 用你习惯的方式把 IPA 放到服务器上（rsync / SMB / scp 都可以）
rsync -P Zelda.ipa server:/path/to/linux/data/import/
# 2. 网页上点上传，打开 "Server" 开关，从下拉列表里选 Zelda.ipa，按平常一样选描述文件和选项后提交
```

整个过程里 IPA 不会通过 HTTP 传输，也不会被整份复制：

| 步骤 | 做法 |
| --- | --- |
| 导入 | `import_dir` 里的文件通过**硬链接**进入服务端存储（零拷贝），原文件留着，可以换参数再签 |
| builder 读取 | 任务里带着未签名文件在服务端磁盘上的路径（`local_transfer_dir` 开启时），builder 直接从这个文件解压，不下载 |
| 重新打包 | **增量回写**：`zip -O` 从原包读、写出新包，只替换签名时改过的文件（可执行文件、Info.plist、`_CodeSignature`、embedded.mobileprovision）。几 GB 的游戏镜像按原压缩数据直接拷贝，不再重新 deflate。服务端的原包不会被改动 |
| 交回 | builder 把签好的文件路径交给服务端，服务端 rename 进存储（同一文件系统，零拷贝） |

为了让硬链接和 rename 生效，`import_dir`、`local_transfer_dir`（builder 的工作目录）和 `save_dir` 必须在**同一个挂载点**里。compose 里它们都在 `./data` 下面（`/data/import`、`/data/work`），两个容器里的路径也完全一样。注意：Docker 里两个不同的 bind mount 之间即使底层是同一块盘，也不能 rename / 硬链接。

用 SMB 覆盖 `import` 里的同名文件时，如果客户端是原地改写（而不是写临时文件再改名，rsync 默认是后者），已经导入的那份也会跟着变，因为它们是同一个硬链接。

### 不在同一台机器上时

自动退回 HTTP：未签名包用 curl 单连接流式下载（断点续传、重试；原来的 easydl 会先下 N 个分片再合并，需要两倍空间），签好的包用 tus 6 路并行回传，可以用 `TUS_CHUNK_SIZE_MB` 分块。设置了 `local_transfer_dir`，但 builder 的工作目录不在里面时，服务端会拒绝按路径交回，builder 也会自动改成上传。

浏览器上传小包时，如果前面有 Cloudflare（单个请求限 100 MB），把 `upload_chunk_size_mb` 设成 50。

### 实测

2 核、约 140 MB/s 的云盘，6 GB 随机数据的 RomFS 加 3000 个小 shader 文件：

| | 改造前 | 现在 |
| --- | --- | --- |
| 解压 + 签名 + 打包 | 286 s | 103 s（解压 43 s / 签名 46 s / 打包 14 s） |
| builder 额外占用的磁盘 | 12 GB | 6 GB |
| 内存峰值 | 33 MB | 41 MB |

耗时基本随大小线性增长，16 GB 的包在这类机器上大约 4～5 分钟，磁盘快的话会更短。`sign_timeout_mins` 和 `BUILDER_TIMEOUT_MINS` 默认都是 60。

iOS 本身装超大 IPA 需要手机上有足够的空间（下载加解压）。装不上的话，可以用 nxnative 的 `--romfs separate` 把游戏镜像单独拷到手机上。

## Increased Memory Limit 等内存权限

nxnative 打出来的 IPA 会在主程序的 ad-hoc 签名里请求 `com.apple.developer.kernel.increased-memory-limit`，大一点的游戏没有它会被 iOS 杀掉。

这是**受限权限**：只有描述文件授予了，iOS 才认。在签名时硬塞进去，装机会直接失败。所以：

- 签名用的 entitlements 来自描述文件，App 原来请求的只用来做对比。
- 日志会列出描述文件授予了哪些内存权限（`Profile grants ...: YES/no`）。App 请求了但描述文件没给时，会打出醒目警告；设置 `SIGN_REQUIRE_MEMORY_ENTITLEMENTS=1` 后会直接拒绝签名。
- 要拿到这个权限：在开发者后台给一个**明确的（非通配符）App ID** 勾上 *Increased Memory Limit*，重新生成描述文件。签名时选「使用描述文件的 Bundle ID」（或者自定义成同一个 ID）。通配符 App ID 一般带不了这类能力。

> rcodesign 0.29 的坑：文档里写的 `main:` 作用域对 bundle 的主程序不生效，它会悄悄保留旧签名里的 entitlements。`sign.py` 对主 bundle 改为不带作用域传 entitlements，并给带旧 entitlements 的 framework/dylib 显式传空集。测试会检查描述文件里没有的权限确实被去掉了。

## 网页选项支持情况

| 选项 | 状态 |
| --- | --- |
| 证书 + 描述文件签名（企业 / Ad Hoc / 开发） | ✅ |
| 保留原 ID / 用描述文件的 ID / 自定义 Bundle ID | ✅ |
| 修改显示名称 | ✅ |
| 修补 ID（`-p`）、编码 ID（`-e`）、强制原 ID（`-o`） | ✅ |
| 允许调试、全部设备、Mac 适配、文件共享 | ✅ |
| 注入插件（.dylib / .deb / .zip / .framework） | ✅（LIEF） |
| App Extension 各自独立的 entitlements | ✅ |
| 开发者账号登录模式（fastlane + 2FA） | ❌ 未实现，会明确报错 |

## 环境变量

| 变量 | 作用 |
| --- | --- |
| `SIGNTOOLS_INTERNAL_URL` | builder 访问服务端用的地址，不设置则用服务端下发的 `server_url` |
| `SIGN_NO_LOCAL_TRANSFER` | 设为 1 时不使用同机直传，始终走下载和上传 |
| `SIGN_REQUIRE_MEMORY_ENTITLEMENTS` | 设为 1 时，描述文件缺少 App 请求的内存权限就拒绝签名 |
| `TUS_CHUNK_SIZE_MB` | 回传签名包时的分块大小 |
| `SIGN_FULL_REZIP` | 设为 1 时不做增量回写，完整重新压缩 |
| `SIGN_DOWNLOADER=easydl` | 改回原来的多连接下载器 |
| `SIGN_TIMESTAMP_URL` | 时间戳服务器，默认 `none`（iOS 不需要） |
| `RCODESIGN` | rcodesign 路径 |

## 不用 Docker

需要：Python 3.10+（`pip install cryptography lief`）、Node 18+、`unzip` `zip` `ar`(binutils) `openssl` `curl`，以及 [rcodesign](https://github.com/indygreg/apple-platform-rs/releases)。

```bash
go build -o SignTools-Builder .
mkdir signfiles && cp -r linux/{sign.py,node-utils,libsubstrate} signfiles/ && (cd signfiles/node-utils && npm ci)
./SignTools-Builder -key "$BUILDER_KEY" -files ./signfiles -timeout 60
```

脱离服务端单独调试：在一个目录里放好 `cert.p12 cert_pass.txt prov.mobileprovision team_id.txt unsigned.ipa args.txt id.txt user_bundle_id.txt`，执行 `SIGN_LOCAL_ONLY=1 python3 sign.py`，输出 `signed.ipa`。

## 测试

```bash
linux/tests/e2e.sh                       # 下载上游二进制
SERVER_BIN=... BUILDER_BIN=... BIG_MB=300 LOCAL=1 linux/tests/e2e.sh
```

`LOCAL=1` 测同机模式：把包放进 `import_dir`、按文件名提交（和网页上的 Server 开关一样）、硬链接导入、builder 原地读取并按路径交回，并检查全程没有 HTTP 下载和上传。`LOCAL=outside` 测 builder 不在 `local_transfer_dir` 里时的回退。不设置时走普通 HTTP 模式。需要的服务端特性来自 [NimaQu/SignTools](https://github.com/NimaQu/SignTools)，用 `SERVER_BIN` 指定它编出来的二进制。

测试会用 clang + lld 在 Linux 上编出一个真实的 arm64 iOS 应用：主程序请求 increased-memory-limit，带一个 Share 扩展和一个没有 CFBundleIdentifier 的 framework，并预先签着另一个 Team ID 的旧签名。然后生成仿企业证书和 CMS 签名的描述文件，像网页那样提交任务（`server_url` 故意设成连不上的地址，强制走内网直连），下载签好的 IPA 检查：签名证书、各组件的 Team ID / identifier / entitlements、描述文件没授予的权限确实被去掉、embedded.mobileprovision、可执行权限、主 bundle 的 CodeResources 是否封住了嵌套 bundle 和资源。

**局限**：测试用的是自签的仿造证书，没有在真机上验证过。请先用你的企业证书签一个 App 在真机上装一次，确认没问题再正式使用。
