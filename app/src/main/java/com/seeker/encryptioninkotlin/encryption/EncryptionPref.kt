package com.ft.ecom.encryption

import android.app.Activity
import android.content.Context
import android.content.SharedPreferences


class EncryptionPreferenceManager(internal var _context: Context) {

    /*Created by Vickyy on 11-01-2020*/
    internal var pref: SharedPreferences
    internal var editor: SharedPreferences.Editor

    init {
        pref = _context.getSharedPreferences(Key.ENCRYPTION_PREF_NAME_KEY, Activity.MODE_PRIVATE)
        editor = pref.edit()
    }


    fun getAESkey(): String {
        return pref.getString(Key.ENCRYPTION_PRF_AES_KEY, "").toString();
    }

    fun setAESkey(aes_key: String) {
        editor.putString(Key.ENCRYPTION_PRF_AES_KEY, aes_key).toString();
        editor.commit()
    }


    object Key {
        val ENCRYPTION_PREF_NAME_KEY = "ENCRYPTION_PREF"
        val ENCRYPTION_PRF_AES_KEY = "AES_KEY"
    }


}