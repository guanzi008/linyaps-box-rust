# linyaps-box-rust

`OpenAtom-Linyaps/linyaps-box` 的纯 Rust、命令兼容 OCI 运行时重构。兼容目标冻结在上游提交
[`2f6023b609f500b756b558bf0b87be4e504c53f5`](https://github.com/OpenAtom-Linyaps/linyaps-box/commit/2f6023b609f500b756b558bf0b87be4e504c53f5)，版本输出保持 `2.3.0-dev-` 和 OCI spec `1.3.0`。

`ll-box` 保留冻结版本的 `run`、`exec`、`kill`、`list` 命令、参数、错误文本、状态文件、表格/JSON、console socket、hook 和信号语义。容器生命周期基于仓库内 vendored Youki `libcontainer` Rust 实现，不调用原 C++ 二进制，也不包含 C、C++、Go、Python 或汇编实现源码。

完整行为范围和冻结约束见 [`COMPATIBILITY.md`](COMPATIBILITY.md)。

## 构建测试

要求 Linux 和 Rust 1.88 或更高版本：

```sh
cargo test --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo build --release --locked
```

发布产物为 `target/release/ll-box`。与 `linyaps-rust` 同级检出时，可从主仓执行完整应用运行链：

```sh
../linyaps-rust/tests/system/runtime-e2e.sh
```

## Debian 包

在 Debian/Ubuntu 构建机上安装 `dpkg-dev`、`binutils` 和 Rust 后执行：

```sh
./packaging/debian/build-deb.sh
```

产物为 `dist/linglong-box_<version>_<architecture>.deb` 和
`dist/SHA256SUMS`。也可使用 `DEB_VERSION`、`DEB_ARCH`、`OUTPUT_DIR` 和
`SOURCE_DATE_EPOCH` 覆盖默认元数据。

项目代码许可证为 `LGPL-3.0-or-later`；vendored Youki `libcontainer` 保持其
`Apache-2.0` 许可证，完整文本与冻结上游 REUSE 许可证集合均位于 `LICENSES/`。
