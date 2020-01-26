package com.seeker.encryption.encryption

import android.content.Context
import android.util.Log
import android.widget.Toast
import com.seeker.encryptioninkotlin.BuildConfig

/*Created by Vickyy on 11-01-2020*/

object obj {
    val TAG = "TAG_Encryption"
}

internal fun Logd(userTag: String, log_string: String?) {
    if (BuildConfig.DEBUG) {
        Log.d(obj.TAG, ":$userTag" + ":$log_string")
    }
}

fun Context.toast(toast_str: String?, duration: Int = Toast.LENGTH_SHORT) {
    if (BuildConfig.DEBUG) {
        Toast.makeText(this, toast_str, duration).show()
    }
}
