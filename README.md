# EasyTier Desktop（接口冻结 freeze-v1）

使用 Rust 1.100.0、edition 2024、Cargo resolver 3。当前包含完整的契约、各层 trait
与模型（已冻结）、按工作包归属拆好的空实现文件、开发检查以及 GPUI 空窗口。
**不包含业务逻辑，不会启动内核、安装服务、修改系统网络或回收系统对象。**

## 目录和职责

| crate | 职责 |
| --- | --- |
| etd-contract | 唯一 Protobuf 定义、生成消息、共享 DTO 与契约版本 |
| etd-ipc | 本地 IPC 的连接、监听和对端身份抽象 |
| etd-client | 宿主客户端 trait；仅生成客户端 gRPC 桩 |
| etd-app | 状态仓库、宿主启动接口、配置/托盘抽象、跨线程消息 |
| etd-ui | GPUI Kit 窗口及 UI 组合根 |
| etd-ctl | CLI 组合根，依赖宿主客户端 |
| etd-host | 宿主组合根，负责连接真实适配器 |
| etd-host-core | 宿主编排、授权、内核存储接口；仅生成服务端 gRPC 桩 |
| etd-proc | 进程、时钟、重启策略抽象；唯一 ProcessKit 适配器 |
| etd-sysfx | 副作用记录、账本、回收 trait；SQLite 实现占位 |
| etd-sysfx-os | 系统副作用适配器占位 |
| etd-core-api | 内核适配 trait 与计划模型，不暴露 EasyTier 类型 |
| etd-core-easytier | EasyTier 原型适配器，固定上游提交 |
| etd-testkit | 测试替身、内存传输、fake-core 占位 |
| xtask | 工作区依赖边界检查 |

消息由 etd-contract 使用 prost 生成；etd-client 和 etd-host-core 使用 tonic
分别生成 client/server stubs（各自的 `stub` 模块），通过 extern_path 复用同一个
消息类型。契约 `etd.v1` 已包含架构 v7 列出的全部方法，每个方法用
`(etd.v1.required_role)` 自定义选项标注所需角色，`etd_contract::required_role`
从描述符读出同一张表。契约 1.0 不含用户宿主的“远程”模式（连别处的 rpc-portal、不启动内核），以后作为兼容新增补上。

## 接口冻结与文件归属

冻结接口（改动走变更请求）：`crates/etd-contract/**`、`buf.yaml`、根及各 crate 的
`Cargo.toml` 与 `lib.rs`、各 trait 与模型文件、`etd-testkit/src/lib.rs` 与
`fakes/mod.rs`。每个实现文件开头写明归属的工作包（见 doc#7 归属表）。加字段、
加枚举变体（枚举一律 `#[non_exhaustive]`，少数安全相关的判定枚举除外）、加默认
实现的方法算兼容改动；签名改动算破坏。

契约描述符基线在 `crates/etd-contract/tests/baseline/etd.v1.txt`；兼容的新增
用 `ETD_UPDATE_BASELINE=1 cargo nextest run -p etd-contract` 重新生成并随改动评审。
各 crate 的依赖已按 doc#4 一次加齐，未使用的依赖由 `[workspace.lints.cargo]`
暂时放行，第 1 波合并后再收紧。

## 本地检查

准备 Rustup、平台 C/C++ 工具链、protoc 36.2。仓库中的 rust-toolchain.toml
固定工具链及 rustfmt/clippy；Cargo.lock 固定解析后的依赖。

Windows 需要 MSVC 和 Windows SDK；macOS 需要 Xcode Command Line Tools；
Linux 需要 GPUI 所需的原生构建、图形和窗口系统开发库，可参考 CI 的安装步骤。

```sh
cargo fmt --all -- --check
cargo build --workspace --locked
cargo clippy --workspace --locked -- -D warnings
cargo test --workspace --locked
cargo xtask check-boundaries
cargo run -p etd-ui
```

若已安装 cargo-nextest，可用 `cargo nextest run --workspace --locked`，
另运行 `cargo test --doc --workspace --locked`。依赖审计用 `cargo deny --locked check`；
契约检查用 `buf lint` 和 `buf breaking --against '.git#tag=freeze-v1'`。
这些是额外工具，不由本仓库自动安装。

## 依赖边界

`cargo xtask check-boundaries` 读取 Cargo metadata 的实际解析图及声明：

1. etd-ui、etd-app、etd-client 的整个依赖闭包不得有 etd-core-easytier 或 easytier*。
2. 工作区只有 etd-proc 可以直接依赖 ProcessKit；系统 API 绑定仅允许
   etd-proc、etd-ipc、etd-sysfx-os 直接依赖（第三方库自己的传递依赖不算直接引用）。
3. etd-host-core 只依赖公共契约及 trait 层，不直接引用真实系统/内核适配器。
   测试可通过 dev-dependency 使用 etd-testkit，产品不得普通依赖 testkit。

检查包含 normal/build/dev，以及所有目标条件和工作区 feature；违反任何边界时
以非零退出码告警，CI 失败。

## 依赖选择

GPUI Kit 固定 0.11.0（上游 GPUI snapshot 0.3.14），不启用 Fast/Shell；
Linux 托盘选择 ksni/snapshot，关闭 GTK 默认后端。ProcessKit 固定 3.3.4；
prost/tonic 系列分别固定 0.14.6/0.14.9。SQLite 使用 bundled；
时间戳使用 Jiff 1.0，单调时钟使用 std::time。

EasyTier 原型固定上游提交 c97f36b8d40f3bde7a95cc9ec99fe95fe35a6ff0，
关闭默认 features。未实现的业务不盲目引入候选依赖；按需增加，并统一写在
workspace.dependencies 中。上游间接依赖版本不做全局覆盖。

## 许可

LGPL-3.0-or-later。见 LICENSE（LGPL 第 3 版）及 COPYING-GPL-3.0
（LGPL 引用的 GPL 第 3 版全文）。第三方及独立发布的组件保留各自许可。
