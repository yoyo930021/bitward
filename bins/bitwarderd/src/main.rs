//! bitwarderd：每裝置唯一的中樞進程（契約 §1）。
//! U6 填入：UDS 監聽、Call 分派（唯一入口 `call()`）、狀態機組裝。

fn main() {
    // U6: 解析引數 → tokio runtime → bw_btp serve
    println!("bitwarderd {} (skeleton)", env!("CARGO_PKG_VERSION"));
}

#[cfg(test)]
mod tests {
    #[test]
    fn skeleton_compiles() {}
}
