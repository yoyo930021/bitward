# 文件地圖

- `ARCHITECTURE.md` — 現行架構與 P0–P6 進度總表（**先讀這份**；每節附證據腳本名）。
- `design/`
  - `android-findings.md` — Android 實測紀錄：nsh 打包缺口、Gradle 外殼方案、孤島接線計畫、已知缺陷（鏡像目錄、reindex）。
  - `candidate-1-daemon-hub.md` / `candidate-2-everything-spoke.md` — 初始設計空間的兩個競爭原型（存檔參考；勝出形態已併入 ARCHITECTURE）。
- `research/`
  - `protocol.md` — 上游 Bitwarden/Vaultwarden HTTP API 調查（授權、SDK、端點形態）。
  - `btp-frames.md` — **BTP 線協定幀層規格**：length-prefix 佈局、JSON/postcard 协商、
    混版本矩陣、conformance vectors（`cargo test -p bw-btp --test vectors` 執行）。
  - `macos-provider.md` — AuthenticationServices provider 能力邊界研究。
  - `feature-gaps.md` — 對照官方客户端的功能盤點。
  - `agent-ecosystem.md` / `prior-art.md` — agent 生態與前例調查。
- 平台落地紀錄（就近原則，不在本目錄）：
  - `platforms/macos/FINDINGS.md` — macOS App/provider 簽章、BTM/SMAppService 實驗全紀錄（含 2026-11-07 G2 收案）。
  - `apps/bitward-android/android-shell/README.md` — Android 外殼建置與孤島銜接方案。
  - `apps/bitward-gui/README.md` — NSH 桌面 App。
- e2e：`dev/e2e/*.sh`（readpath/writepath/agentpath/remotepath/datamanagement/orgpath/android-app…），每條對應 ARCHITECTURE 的 P 線斷言。
