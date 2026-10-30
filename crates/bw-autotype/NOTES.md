# bw-autotype NOTES

## 依賴選型（來源 URL）
- 採用 `core-graphics` 0.25.0（2025-05，servo 維護）：
  <https://crates.io/crates/core-graphics>，repo <https://github.com/servo/core-graphics-rs>。
  提供 `CGEventSource::new` / `CGEvent::new_keyboard_event` / `set_string` / `post`，
  且 `CGEventSource` 為 foreign-type（Clone = CFRetain），可安全重用了事件源。
- 未選 `objc2-quartz` 0.3.2（2025-10，更新）：解包檢查其 src 僅含
  ImageKit、QuartzFilters 模組，**無任何 CGEvent/CoreGraphics 事件綁定**，
  換它等於自己再刻 extern 宣告。待 objc2 補上 CG 事件綁定後可平移。

## API 依據
- unicode 注入：`CGEventKeyboardSetUnicodeString`（core-graphics 的 `CGEvent::set_string` 即其包裝）
  <https://developer.apple.com/documentation/coregraphics/1455616-cgeventkeyboardsetunicodestring>
  ——事件附帶字串時按 unicode 出口進棧，不經鍵盤佈局映射，故中文/特殊字元密碼不受佈局影響。
- 鍵事件建立/投递：`CGEventCreateKeyboardEvent` + `CGEventPost(kCGHIDEventTap)`
  <https://developer.apple.com/documentation/coregraphics/cgeventcreatekeyboardevent(forkeycode:keydown:)>
- 虛擬鍵碼 kVK_Tab=0x30、kVK_Return=0x24：Apple `HIToolbox/Events.h`
  <https://github.com/phracker/MacOSX-SDKs/blob/master/MacOSX10.13.sdk/System/Library/Frameworks/Carbon.framework/Versions/A/Frameworks/HIToolbox.framework/Versions/A/Headers/Events.h#L197-L327>
  （core-graphics `event::KeyCode::{TAB,RETURN}` 同值，本 crate 以 `VK_TAB`/`VK_RETURN` 常數固化）。
- 鍵間距 10–20ms 的依據：xdotool `type` 預設即 12ms
  <https://github.com/jordansissel/xdotool/blob/master/cmd_type.c#L29>
  （「12ms between keystrokes default」）。太快會被部分 app 的事件佇列吞鍵；
  本 crate 取 `KEY_INTERVAL = 12ms`。
- unicode 事件附帶的 keycode 只是載體（set_string 覆寫文字負載），故用 `KeyCode::ANSI_A` 佔位。
- 官方 Bitwarden 桌面端的 macOS autotype 截至 clients@main 仍是 `todo!()`
  （apps/desktop/desktop_native/autotype/src/mvp/macos.rs），無官方 macOS 參數可抄，
  以上為外部先例彙整。

## 真機驗證前提（給 Main）
- daemon 進程需要「輔助使用」（Accessibility）權限才能 post 按鍵事件；
  未授權時事件靜默丟失（CGEventPost 不回錯）——先授權再測。
- 倒數 3 秒 + 12ms 鍵距 → 預設模板全程 <4s；焦点視窗在 post 瞬間決定收鍵對象。
