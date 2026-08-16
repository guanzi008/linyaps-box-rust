# Compatibility Baseline

## 冻结目标

- 上游仓库：[`OpenAtom-Linyaps/linyaps-box`](https://github.com/OpenAtom-Linyaps/linyaps-box)
- 冻结提交：`2f6023b609f500b756b558bf0b87be4e504c53f5`
- 对外版本：`2.3.0-dev-`
- OCI state/spec 版本：`1.3.0`

兼容判断以冻结提交的实际二进制、源码运行路径和状态格式为准。

## 已覆盖接口

- 全局选项、环境变量及 `run`、`exec`、`kill`、`list` 四个命令。
- 冻结 CLI11 帮助、版本、校验、错误码、错误文本和参数边界行为。
- OCI bundle 校验、rootfs、namespace、user mapping、mount、capability、rlimit、sysctl 和进程启动。
- 前台/后台运行、console socket、TTY、preserve-fds、信号转发、退出状态和清理。
- OCI hook 状态扩展、执行顺序、超时、环境隔离及 poststop 容错。
- `exec` 的 process JSON、用户、工作目录、环境、capability、TTY 和 namespace 进入。
- 冻结状态文件、`list` 表格/JSON、`kill --all`、日志文本/JSON/syslog/journal 兼容输出。
- Linyaps 扩展：`ns_last_pid`、hook 元数据、默认 runtime 根目录及兼容错误转换。

## 冻结约束

- 冻结运行时只支持 disabled cgroup manager；其他 manager 仍返回相同的不支持错误。
- 冻结源码解析并校验 seccomp，但容器运行路径明确保留 TODO，未安装过滤器；本实现保持这一实际语义。
- Youki 的通用实现被裁剪为本运行时需要的 Rust feature；Linux 默认依赖树不编译 C/C++ 对象。

## 验证门

持续集成执行：

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
cargo build --release --locked
```

测试覆盖 CLI、配置归一化、状态、日志、hook、exec、信号、console、生命周期和错误映射；另有冻结 `ll-box-st` 套件及 C++/Rust 差分矩阵。与 `linyaps-rust` 配对后，`tests/system/runtime-e2e.sh` 验证 builder 导入、package manager、CLI、OCI runtime、`ll-init` 和应用退出清理的完整链路。
