package io.bitward.android

import android.app.Activity
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
 * 零業務語意：值不經 Kotlin 手，全部由系統餵給 AutofillService。
 */
class AutofillProbeActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val pad = (16 * resources.displayMetrics.density).toInt()
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad, pad, pad)
        }
        val user = EditText(this).apply {
            hint = "probe-user"
            inputType = InputType.TYPE_CLASS_TEXT or
                InputType.TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_YES
            setAutofillHints(View.AUTOFILL_HINT_USERNAME)
        }
        val pass = EditText(this).apply {
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
        root.addView(user)
        root.addView(pass)
        root.addView(submit)
        setContentView(root)
    }
}
