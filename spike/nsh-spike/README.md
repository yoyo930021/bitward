# nsh-spike

契約 §0.2 的 NSH GUI spike（P0）：provider 設定頁 + vault 列表兩個純 Rust 畫面，
資料直接反序列化 `bw_proto::ItemMeta`（`fixtures/items.json`）。本 app 無 TSX，
`nsh test` 只跑 cargo 端。結論見 `FINDINGS.md`，魔術常數來源見 `NOTES.md`。

```sh
nsh run --target macos                      # 開窗；mod+1/2 切頁、mod+3 開詳情、escape 返回
NSH_SPIKE_SHOTS=$PWD nsh run --target macos # 背景 launchd session 用：自我截圖 shot-1..3.png 後退出
```

以下为 `nsh init` 原始說明：

An app written in Rust: its UI is `src/lib.rs`, and `nsh.json` names the root component (`"root": "App"`).

```sh
nsh run                      # this machine's backend; --target ios, android, web, macos, linux or windows
nsh check                    # cargo check of the crate, then type checks App.test.tsx
nsh test                     # cargo test, then App.test.tsx: the root tested from TypeScript, headless; --target to run it on a platform
nsh test nsh.json --trace    # headless: what the root mounts, and the time of each commit
nsh package --target web     # or ios, android, macos, linux, windows
```

`nsh run` and `nsh package` mount the root on every platform, the browser included, without QuickJS: the app is Rust
and native code from start to end (in the browser, with NSH's page script). Rust edits rebuild and restart the app.

```sh
cargo run
```

This starts the root directly on the machine's native desktop backend: GTK 4 on Linux, AppKit on macOS, Win32 on
Windows. Install the backend's development libraries before building.

The `nsh` commands build the app's runners from the NSH crates `Cargo.toml` depends on: crates.io's at the version of
the `nsh` you run (keep the `nsh-*` dependencies at that version when you upgrade `nsh`), or an NSH checkout's by path.

## Adding a TSX entry

TSX screens can use the Rust components and modules, with hot reloading for the TSX. The crate's set,
`#[native_module("nsh-spike/native")]` in `src/lib.rs`, already exports `App`. Add an `App.tsx`:

```tsx
import { mount } from "nsh";
import { App } from "nsh-spike/native";

mount(App);
```

then run it with `nsh run App.tsx` (`tsconfig.json` is there for it and the test): a named TSX entry
runs on QuickJS, while `nsh run` alone keeps running the Rust root. The first `nsh build App.tsx` writes the TypeScript
declarations of `nsh-spike/native` into `.nsh/types`. Register more with `registry.register::<…>()` (components),
`registry.module::<…>()` and `registry.class::<…>()`.

NSH-generated files stay in `.nsh/`: runner sources in `.nsh/rust/` and default packages in `.nsh/out/`.
Cargo keeps its normal `target/` directory and respects your existing `CARGO_TARGET_DIR`.
