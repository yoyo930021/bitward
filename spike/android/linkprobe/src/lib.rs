//! 假設 3 的連結探針：純 bw-crypto 呼叫鏈，cdylib 強制 cross-link。
//! 目的不是跑，是記錄 `cargo build --target aarch64-linux-android`
//! 需要哪些 C 工具鏈參數（linker/ar）。

pub fn probe() -> usize {
    let mk = bw_crypto::master_key(
        "pw",
        "user@example.com",
        bw_crypto::KdfParams::Pbkdf2 { iterations: 1 },
    )
    .expect("pbkdf2 master key");
    mk.as_bytes().len()
}
