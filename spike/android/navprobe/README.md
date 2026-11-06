# Android 導航容器探針

契約 §0.2 起押注前的確認項：nsh 0.3.0 的 `nav_stack`/`nav_page`/`dialog`
在 **Android views 後端**到底渲不渲染（macOS dev host 上 `spike/nsh-spike`
卡點 4 是「掛得上但內容區整塊不渲染」）。結論與證據在
`docs/design/android-findings.md` 的「P4b 第一批」節。

```sh
export PATH="$HOME/.local/bin:$PATH" ANDROID_HOME=$HOME/Library/Android/sdk
nsh package --target android --run            # 建三 ABI、adb install、啟動
ADB=$ANDROID_HOME/platform-tools/adb
$ADB exec-out screencap -p > /tmp/probe.png    # 像素
$ADB shell uiautomator dump /sdcard/u.xml && $ADB pull /sdcard/u.xml /tmp/u.xml   # view 層級
$ADB logcat -d | grep probe:                   # 事件是否送達 Rust
$ADB shell input keyevent 4                     # 系統返回鍵
```

app 起點是兩頁棧（`probe-a` 在底、`probe-b` 在上）。要驗的四件事：
靜態 push 的頂頁內容渲染、`when` 區域增減頁面＝原生 push/pop、
`dialog()` 呈現、系統返回鍵會 pop 並觸發 `on_dismiss`。

A 頁另外排了三個按下Sent測試（`A1` 直接放在 `scroll()` 裡、`A2` 放在 `when` 區域裡、
`A4` 放在一個 `input()` 之後），用來分辨「按了沒反應」是容器問題還是驅動問題：
三個都會觸發（logcat `probe: A1/A2/A4`）。實測比較有杀伤力的是 adb 本身——軟鍵盤
開著時第一個 `input tap` 被 IME 收掉、送不到 app，結論與细节在
`docs/design/android-findings.md` 的「adb 驅動陷阱」。
