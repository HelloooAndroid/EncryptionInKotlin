package com.seeker.encryptioninkotlin.encryption.utils

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.annotation.RequiresApi
import com.ft.ecom.encryption.Encryption.Key.AES_MODE
import com.ft.ecom.encryption.Encryption.Key.AndroidKeyStore
import com.ft.ecom.encryption.Encryption.Key.FIXED_IV
import com.ft.ecom.encryption.Encryption.Key.KEY_ALIAS
import com.ft.ecom.encryption.EncryptionPreferenceManager
import com.ft.ecom.encryption.Logd
import java.io.IOException
import java.security.*
import java.security.cert.CertificateException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/*Created by Vickyy on 12-01-2020*/
class AesUtils(var context: Context) {


    //val pref_encryption = EncryptionPreferenceManager(context)
    var keyStore: KeyStore? = null
    private val TAG = "TAG_AesUtils:"

    /*Generate random key for AES
    * @RequiresApi (M) required and wont affect the module since we have check on method calling
    * Store key in Keystore*/
    @RequiresApi(api = Build.VERSION_CODES.M)
    @Throws(CertificateException::class, NoSuchAlgorithmException::class,
        IOException::class, KeyStoreException::class,
        InvalidAlgorithmParameterException::class, NoSuchProviderException::class
    )
    fun generateKey(): SecretKey? {
        keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore?.load(null)
        if (! keyStore?.containsAlias(KEY_ALIAS)!!) {
            val keyGenerator: KeyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, AndroidKeyStore)
            keyGenerator.init(KeyGenParameterSpec.Builder(KEY_ALIAS,KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(false)
                .build()
            )
            return keyGenerator.generateKey()
        }
        return null
    }

    /*Encrypt with AES
     @RequiresApi (K) required and wont affect the module since we have check on method calling
    */
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    @Throws(java.lang.Exception::class)
    fun encryptMsg(message: String?): String? {
        var cipher: Cipher = Cipher.getInstance(AES_MODE)
        cipher.init(Cipher.ENCRYPT_MODE, getSecretKey(), GCMParameterSpec(128, FIXED_IV))
        val cipherText: ByteArray = cipher.doFinal(message?.toByteArray())
        Logd(TAG+"PRINT_EncryptFrom", message)
        Logd(TAG+"PRINT_EncryptTo", Base64.encodeToString(cipherText, 0))
        return Base64.encodeToString(cipherText, 0)
    }


    /* Decrypt the message, given derived encContentValues and initialization vector. */
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    @Throws(java.lang.Exception::class)
    fun decryptMsg(cipherText: String): String {
        val cipherText_byte = Base64.decode(cipherText, 0)
        val cipher: Cipher = Cipher.getInstance(AES_MODE)
        cipher.init(Cipher.DECRYPT_MODE, getSecretKey(), GCMParameterSpec(128, FIXED_IV))
        val decryptByte: ByteArray = cipher.doFinal(cipherText_byte)
        Logd(TAG+"PRINT_DecryptFrom", cipherText)
        Logd(TAG+"PRINT_DecryptTo", decryptByte.toString(Charsets.UTF_8))
        return decryptByte.toString(Charsets.UTF_8)
    }


    /*Get Secret key from Keystore*/
    @Throws(Exception::class)
    fun getSecretKey(): Key? {
        return keyStore!!.getKey(KEY_ALIAS, null)
    }




}