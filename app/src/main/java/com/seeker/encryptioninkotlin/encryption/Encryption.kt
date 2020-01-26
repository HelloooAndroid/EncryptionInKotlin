package com.ft.ecom.encryption

import android.app.Activity
import android.content.Context
import android.os.Build
import android.widget.Toast
import com.seeker.encryptioninkotlin.encryption.utils.AesUtils
import com.seeker.encryptioninkotlin.encryption.utils.RsaUtils
import java.security.KeyStore

/*Created by Vickyy on 11-01-2020*/

class Encryption(var context: Context) {
    var mContext = context

    var aesUtils = AesUtils(context)
    var rsaUtils = RsaUtils(context)

    init {
        generateKey()
    }


    /*Generate key as per Build.VERSION
    * Symmetric key generation and storage in the Android KeyStore is supported from Android 6.0 (API Level 23) onwards.
      Asymmetric key generation and storage in the Android KeyStore is supported from Android 4.3 (API Level 18) onwards.
    */
    private fun generateKey() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            aesUtils.generateKey()
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR2 && Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            rsaUtils.generateRSA_KeyPair()
            rsaUtils.generateAndStoreAES()
        }
    }

    /*Keys required for both AES and RSA encryption*/
    object Key {
        val KEY_ALIAS = "KEY_ALIAS"
        val AndroidKeyStore = "AndroidKeyStore"
        val RSA_MODE = "RSA/ECB/PKCS1Padding"
        val AES_MODE = "AES/GCM/NoPadding"  /*"AES/ECB/PKCS7Padding"*/
        val ANDROID_STORE_WORKAROUND = "AndroidKeyStoreBCWorkaround"
        val ANDROID_OPEN_SSL = "AndroidOpenSSL"
        val FIXED_IV = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12) //initialization vector

    }


    /*Encryption*/
    fun encrypt(input: String?) : String? {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            return aesUtils.encryptMsg(input)
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR2 && Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            return rsaUtils.encrypt(input?.toByteArray())
        }
        context.toast("SDK version is less than JELLY_BEAN_MR2 \n Hence, Encryption is not possible", Toast.LENGTH_LONG);
        return "";
    }

    /*Decryption*/
    fun decrypt(input: String) : String? {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            return aesUtils.decryptMsg(input)
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR2 && Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            return rsaUtils.decrypt(input)
        }else{
            return null;
        }
    }








}

