package io.bitward.android

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.text.InputType
import android.util.Log
import android.view.View
import android.view.autofill.AutofillManager
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout

/**
 * e2e 專用填充探針頁（A16：save 全鏈驗收）。
 *
 * 存在的理由：系統只在「表單提交」且上一次 FillResponse 帶了 SaveInfo 時
 * 才發 onSaveRequest；真 app 的提交時機各家不同，驗收要一根確定性的槓桿。
 * 本頁＝帳號＋密碼兩個 hint 欄＋提交鈕，提交鈕直接呼叫
 * `AutofillManager.commit()`（文件化的「收集完畢」訊號，觸發存檔流程）。
 * 零業務語意：e2e 值經 intent extras `setText` 進欄，帳密由系統從欄位現值
 * 收進 AutofillService，Kotlin 端不碰存檔內容。
 */
class AutofillProbeActivity : Activity() {

    private var user: EditText? = null
    private var pass: EditText? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val pad = (16 * resources.displayMetrics.density).toInt()
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad, pad, pad)
            // targetSdk 35 強制 edge-to-edge：不吃 insets 的話第一欄落在
            // 狀態欄底下，tap 打在系統欄上、欄位永遠拿不到 focus（A16 實錄）。
            fitsSystemWindows = true
        }
        user = EditText(this).apply {
            hint = "probe-user"
            inputType = InputType.TYPE_CLASS_TEXT or
                InputType.TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_YES
            setAutofillHints(View.AUTOFILL_HINT_USERNAME)
        }
        pass = EditText(this).apply {
            hint = "probe-pass"
            inputType = InputType.TYPE_CLASS_TEXT or
                InputType.TYPE_TEXT_VARIATION_PASSWORD
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_YES
            setAutofillHints(View.AUTOFILL_HINT_PASSWORD)
        }
        val submit = Button(this).apply {
            text = "提交"
            setOnClickListener {
                getSystemService(AutofillManager::class.java)?.commit()
                Log.i(ISLAND_TAG, "probe commit requested")
            }
        }
        // 欄位間距放大：autofill 面板錨在 focus 欄下方，緊貼的下一欄／鈕會
        // 被面板蓋住——e2e 的 tap 會誤命中候選列（實測教訓同 A9 段）。
        fun gap(dp: Int) = View(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                (dp * resources.displayMetrics.density).toInt(),
            )
        }
        root.addView(user)
        root.addView(gap(260))
        root.addView(pass)
        root.addView(gap(140))
        root.addView(submit)
        setContentView(root)
        applyExtras(intent)
    }

    // e2e 走 singleTop 二段式：先空欄啟動＋focus（autofill session 以空值開局），
    // 再 `am start --es user/pass` 經 onNewIntent setText＝session 內的淨變更。
    // 為何不能 onCreate 一次預填完（實錄）：存檔 UI 的判定是「必要欄現值不同於
    // session 初始快照」（Session.showSaveLocked：net-zero 補打再刪同樣回
    // 「with no changes, comes no responsibilities」），預填早於 focus 就永遠
    // 「未變更」、onSaveRequest 不發。
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        applyExtras(intent)
    }

    private fun applyExtras(intent: Intent) {
        intent.getStringExtra("user")?.let { v -> user?.setText(v) }
        intent.getStringExtra("pass")?.let { v -> pass?.setText(v) }
    }
}
