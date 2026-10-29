# bitward-nm

瀏覽器 native messaging ↔ BTP 純管道（契約 §1）。零政策邏輯：授權、budget、核准、
審計全在 daemon；shim 只做協定轉譯。環境：`BITWARD_SOCK`（必要）、
`BITWARD_DATA_DIR`（session token 存 `<data_dir>/nm_session`）。
daemon 重啟（unknown session）⇒ 自動重配對一次。

**政策邊界**：`credential.reveal` 回明文——瀏覽器對面是「人」，不是 LLM context
（§2.7 出口登記表：MCP 面預設 metadata-only；這裡的 reveal 每次都在 daemon 落 audit）。
`credential.match` 屬 Metadata 級：只回 `id/name/uris/username_hint:null`（P4 前不回 username）。

## 安裝

    bitward-nm install-manifest --browser chrome --extension-id <32-char-id>
    # Firefox 可加 --dest <profile 目錄>；印出寫入的 manifest 路徑

## Chrome extension 連線範例

    const port = chrome.runtime.connectNative("com.bitward.client");
    port.onMessage.addListener((m) => console.log(m)); // {id, ok, result} | {id, ok:false, error}
    port.postMessage({ id: 1, method: "credential.match",
                       params: { uri: location.href } });

Methods：`ping`、`session.info`、`vault.list`、`credential.match {uri}`、
`credential.reveal {id}`。`result` 為 daemon Response 原樣 serde 形態
（如 `{"Version":"..."}`、`{"Items":[...]}`；match 為陣列）。stdin EOF ⇒ 乾淨結束；
BTP 斷線 ⇒ 所有 pending 回 error 後結束。
