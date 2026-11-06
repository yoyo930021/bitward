package io.bitward.android

import android.app.Service
import android.content.Intent
import android.os.IBinder
import android.util.Log

/**
 * in-process 中樞的保命外殼（契約 §1：「Android 為 app 內 in-process 等位物，
 * foreground service」）。
 *
 * 角色：讓承載 `libnsh.so` 中樞的程序在背景時不被系統回收，並在中樞起來後
 * 把 [`BitwardAutofillService.HubBridge`] 實作註冊進 [`HubHolder`]。
 *
 * 已進 APK（`android-shell/`）；startForeground＋Rust 側週期 sync／UnifiedPush
 * 喚醒是 P4b 第二批（通知權限也要一併補）。
 */
class HubService : Service() {

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.i(ISLAND_TAG, "hub service startCommand")
        // TODO(P4b 第二批): startForeground(NOTIFICATION_ID, 通知) + 接上 Rust 側
        // 的週期 sync / UnifiedPush 喚醒（契約 §1.2 推播路徑）。
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null
}
