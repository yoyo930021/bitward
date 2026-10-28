//! bitward CLI：一次性短命 thin client（契約 §3.10）。
//! U6 填入子命令；輸出契約：--json 永不含 Secret 級欄位，除非 --reveal 且 TTY。

fn main() {
    // U6: clap parse → 連 daemon → 印結果
    println!("bitward {} (skeleton)", env!("CARGO_PKG_VERSION"));
}

#[cfg(test)]
mod tests {
    #[test]
    fn skeleton_compiles() {}
}
