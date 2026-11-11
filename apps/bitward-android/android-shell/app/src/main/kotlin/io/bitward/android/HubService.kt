package io.bitward.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.job.JobInfo
import android.app.job.JobParameters
import android.app.job.JobScheduler
import android.app.job.JobService
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.util.Log
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * in-process 中樞的保命外殼（契約 §1：Android 為 app 內 in-process 等位物，
 * foreground service）＋背景同步載具（路線 3）。
 *
 * 形態（第五批落地）：
 * - **startForeground**：`dataSync` 類型（manifest 已宣告）；33+ 通知權限未給
 *   時照樣起 foreground（通知只是不可見），並經 [PermissionRequestActivity]
 *   補要一次（每進程最多一次，不煩）。
 * - **背景輪**：drain 收斂（連續失敗退避 30s→10min，純函數在 Rust
 *   `hub::drain_backoff`）＋距上次 pull 超過 15 分鐘順手拉。時序判定全在
 *   Rust（`Hub::background_run`），這裡只管生命週期：乾活時掛 foreground，
 *   收工 `stopForeground`＋`stopSelf`——dataSync FGS 有 6 小時預算（12+），
 *   常駐不回前景才吃得光，所以**不做無限期常駐**。
 * - **排程器＝JobScheduler（不用 WorkManager）**：本專案零 androidx（外殼
 *   一貫紀律，见 README）；WorkManager 會拖進 androidx 全家桶換來的只是
 *   約束組合與存活率最佳化，這裡的需求只有「15 分鐘週期＋網路可用」，
 *   平台 `JobServiceImpl`／`JobService` 直達。週期下限 15 分鐘恰好就是
 *   契約節拍，沒有被平台閹掉的妥協。
 *
 * 觸發源：解鎖成功點（Rust 經 `KeyStoreBridge.ensureHubService`）、
 * JobScheduler 15 分鐘週期、e2e 強制 tick（`am start-foreground-service -a
 * io.bitward.android.action.RUN`）。鎖態時背景輪回 `locked` 即刻收工
 * （封存存在與否由 logcat 的 hasSealed 軌跡判斷，A19/A20 斷言點）。
 */
class HubService : JobService() {

    companion object {
        const val ACTION_RUN = "io.bitward.android.action.RUN"
        const val JOB_ID = 1001
        const val SYNC_PERIOD_MS = 15L * 60_000L
        private const val NOTIF_ID = 41
        private const val CHANNEL_ID = "bitward-hub"
        private const val STOP_GRACE_MS = 20_000L

        /** 15 分鐘週期同步（冪等：同 id 重排即覆寫）。 */
        fun scheduleJob(ctx: Context) {
            val js = ctx.getSystemService(Context.JOB_SCHEDULER_SERVICE) as JobScheduler
            val job = JobInfo.Builder(JOB_ID, ComponentName(ctx, HubService::class.java))
                .setPeriodic(SYNC_PERIOD_MS)
                .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
                .setPersisted(false)
                .setRequiresBatteryNotLow(true)
                .build()
            runCatching { js.schedule(job) }
                .onFailure { Log.w(ISLAND_TAG, "job schedule failed: ${it.message}") }
        }
    }

    private val worker = Executors.newSingleThreadExecutor { r ->
        Thread(r, "bitward-hub-bg").apply { isDaemon = true }
    }
    private val busy = AtomicBoolean(false)
    private var jobParams: JobParameters? = null

    /** 收工寬限：本地 vault 的輪次只有毫秒級，即起即停讓外部觀察者（與後續
     *  寫入）全踩空；留 20 秒吸收連發 mutation（免 FGS 重啟抖動）再退前景。 */
    private val handler = android.os.Handler(android.os.Looper.getMainLooper())
    private val stopRunnable = Runnable {
        runCatching {
            if (Build.VERSION.SDK_INT >= 24) stopForeground(STOP_FOREGROUND_REMOVE)
            else @Suppress("DEPRECATION") stopForeground(true)
        }
        stopSelf()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.i(ISLAND_TAG, "hub service startCommand action=${intent?.action}")
        goForeground()
        kick(null)
        // 週期與事件都會再踢；死掉由 JobScheduler 兜底，不需要 START_STICKY 重放。
        return START_NOT_STICKY
    }

    override fun onStartJob(params: JobParameters?): Boolean {
        Log.i(ISLAND_TAG, "hub service job fired")
        goForeground()
        kick(params)
        return true // 工作在 worker 線程上，jobFinished 另行結算。
    }

    override fun onStopJob(params: JobParameters?): Boolean {
        Log.i(ISLAND_TAG, "hub service job stopped")
        return true // 沒做完就被系統掐掉：請重排。
    }

    private fun kick(params: JobParameters?) {
        if (params != null) jobParams = params
        handler.removeCallbacks(stopRunnable) // 寬限期內新活：收回停機排程
        if (!busy.compareAndSet(false, true)) return
        worker.execute {
            var status: String? = null
            try {
                status = NativeHub.nshBackgroundRun()
            } catch (e: Throwable) {
                Log.w(ISLAND_TAG, "background run threw: ${e.javaClass.simpleName}")
            }
            Log.i(ISLAND_TAG, "hub service round status=$status sealed=${NativeHub.nshHasSealed()}")
            busy.set(false)
            val jp = jobParams
            jobParams = null
            if (jp != null) runCatching { jobFinished(jp, false) }
            wrapUp()
        }
    }

    private fun wrapUp() {
        handler.postDelayed(stopRunnable, STOP_GRACE_MS)
    }

    private fun goForeground() {
        val ctx: Context = this
        val nm = ctx.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= 26) {
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "背景同步", NotificationManager.IMPORTANCE_LOW),
            )
        }
        if (Build.VERSION.SDK_INT >= 33 &&
            ctx.checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED && !permissionAsked
        ) {
            permissionAsked = true
            runCatching {
                ctx.startActivity(
                    Intent(ctx, PermissionRequestActivity::class.java)
                        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                )
            }
        }
        val notif: Notification = if (Build.VERSION.SDK_INT >= 26) {
            Notification.Builder(ctx, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION") Notification.Builder(ctx)
        }
            .setSmallIcon(R.drawable.ic_hub_stat)
            .setContentTitle("Bitwarden 背景同步")
            .setContentText("推送待同步的變更並拉取最新鏡像")
            .setOngoing(true)
            .build()
        startForeground(NOTIF_ID, notif)
    }
}

/** 33+ 通知權限補要（透明、即問即收；每進程最多一次）。 */
class PermissionRequestActivity : android.app.Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (Build.VERSION.SDK_INT >= 33) {
            // 授權窗是獨立系統窗口（GrantPermissionsActivity），宿主即收不影響彈問。
            runCatching {
                requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS), 1)
            }
        }
        finish()
    }
}

private var permissionAsked = false
