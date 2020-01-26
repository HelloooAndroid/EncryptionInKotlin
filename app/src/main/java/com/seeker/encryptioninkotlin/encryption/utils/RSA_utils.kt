package com.seeker.encryptioninkotlin.encryption.utils

import android.content.Context
import android.os.Build
import android.security.KeyPairGeneratorSpec
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.widget.Toast
import com.seeker.encryption.encryption.Logd
import com.seeker.encryption.encryption.toast
import com.seeker.encryptioninkotlin.encryption.Encryption
import com.seeker.encryptioninkotlin.encryption.Encryption.Key.AES_MODE
import com.seeker.encryptioninkotlin.encryption.Encryption.Key.AndroidKeyStore
import com.seeker.encryptioninkotlin.encryption.Encryption.Key.KEY_ALIAS
import com.seeker.encryptioninkotlin.encryption.EncryptionPreferenceManager
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.Key
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.util.*
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream
import javax.crypto.spec.SecretKeySpec
import javax.security.auth.x500.X500Principal

/*Created by Vickyy on 12-01-2020*/

class RsaUtils(var context: Context) {


    val pref_encryption = EncryptionPreferenceManager(context)
    var keyStore: KeyStore? = null
    val TAG = "TAG_RsaUtils:"


    /* 1) Generate RSA key pair*/
    @Throws(Exception::class)
    fun generateRSA_KeyPair() {
        keyStore = KeyStore.getInstance(AndroidKeyStore)
        keyStore?.load(null)
        // Generate the RSA key pairs
        if (!keyStore?.containsAlias(KEY_ALIAS)!!) {

            val kpg: KeyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, AndroidKeyStore)

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                //If Build.VERSION.SDK_INT greater MARSHMELLOW
                kpg.initialize(KeyGenParameterSpec
                    .Builder(KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                    .build())
            } else if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR2 && Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
                //If Build.VERSION.SDK_INT less than MARSHMELLOW
                val start = Calendar.getInstance()
                val end = Calendar.getInstance()
                end.add(Calendar.YEAR, 30)    //Change end validity here, if needed.
                kpg.initialize(
                    KeyPairGeneratorSpec.Builder(context)
                        .setAlias(KEY_ALIAS)
                        .setSubject(X500Principal("CN=$KEY_ALIAS"))
                        .setSerialNumber(BigInteger.TEN)
                        .setStartDate(start.time)
                        .setEndDate(end.time)
                        .build())

            }else{
                context.toast("SDK version is less than JELLY_BEAN_MR2 \n Hence, Encryption is not possible", Toast.LENGTH_LONG);
                return
            }

            kpg.generateKeyPair()

        }
    }

    /* 2) Generate AES using randomization*/
    @Throws(java.lang.Exception::class)
    fun generateAndStoreAES() {
        var enryptedKeyB64 = pref_encryption.getAESkey();
        if (enryptedKeyB64.equals("")) {
            val randomKey = ByteArray(16)
            val secureRandom = SecureRandom()
            secureRandom.nextBytes(randomKey)
            /*3) Encrypt AES with RSA key pair*/
            val encryptedKey: ByteArray = rsaEncrypt(randomKey)
            /*4) Encrypt again with Base64 encode*/
            enryptedKeyB64 = Base64.encodeToString(encryptedKey, Base64.DEFAULT)
            /*5) Store into Shared Pref*/
            pref_encryption.setAESkey(enryptedKeyB64)
        }
    }


    @Throws(java.lang.Exception::class)
    private fun rsaEncrypt(randomKey: ByteArray): ByteArray {
        val privateKeyEntry = keyStore!!.getEntry(KEY_ALIAS, null) as KeyStore.PrivateKeyEntry
        // Encrypt the text
        val inputCipher = getCipher()
        inputCipher?.init(Cipher.ENCRYPT_MODE, privateKeyEntry.certificate.publicKey)
        val outputStream = ByteArrayOutputStream()
        val cipherOutputStream = CipherOutputStream(outputStream, inputCipher)
        cipherOutputStream.write(randomKey)
        cipherOutputStream.close()
        return outputStream.toByteArray()
    }

    /*get Cipher instance depend on Android Version*/
    private fun getCipher(): Cipher? {
        return try {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) { // below android m
                Cipher.getInstance(
                    Encryption.Key.RSA_MODE,
                    Encryption.Key.ANDROID_OPEN_SSL
                ) // error in android 6: InvalidKeyException: Need RSA private or public key
            } else { // android m and above
                Cipher.getInstance(
                    Encryption.Key.RSA_MODE,
                    Encryption.Key.ANDROID_STORE_WORKAROUND
                ) // error in android 5: NoSuchProviderException: Provider not available: AndroidKeyStoreBCWorkaround
            }
        } catch (exception: java.lang.Exception) {
            throw RuntimeException("getCipher: Failed to get an instance of Cipher", exception)
        }
    }


    @Throws(java.lang.Exception::class)
    private fun rsaDecrypt(encrypted: ByteArray): ByteArray? {
        val privateKeyEntry = keyStore!!.getEntry(KEY_ALIAS, null) as KeyStore.PrivateKeyEntry
        val output = getCipher()
        output?.init(Cipher.DECRYPT_MODE, privateKeyEntry.privateKey)
        val cipherInputStream = CipherInputStream(ByteArrayInputStream(encrypted), output)
        val values = ArrayList<Byte>()
        var nextByte: Int
        while (cipherInputStream.read().also { nextByte = it } != -1) {
            values.add(nextByte.toByte())
        }
        val bytes = ByteArray(values.size)
        for (i in bytes.indices) {
            bytes[i] = values[i]
        }
        return bytes
    }


    /*6) Fetch Base64 encrypted AES from Shared Pref and decrypt*/
    @Throws(java.lang.Exception::class)
    private fun getSecretKey(): Key? {
        val enryptedKeyB64 = pref_encryption.getAESkey()
        Logd(TAG,"getSecretKeyBase64:$enryptedKeyB64")
        // need to check null, omitted here
        val encryptedKey = Base64.decode(enryptedKeyB64, Base64.DEFAULT)
        Logd(TAG,"getSecretKey:$encryptedKey")
        /* 7) decrypt again with RSA key pair to get actual AES key*/
        val key = rsaDecrypt(encryptedKey)
        context.toast("Secret key created");
        return SecretKeySpec(key, "AES")
    }




    @Throws(Exception::class)
    fun encrypt(input: ByteArray?): String? {
        val c = Cipher.getInstance(AES_MODE, "BC")
        c.init(Cipher.ENCRYPT_MODE, getSecretKey())
        /*8) now, decrypt data with actual AES key.*/
        val encodedBytes = c.doFinal(input)
        Logd("PRINT_EncryptFrom", String(input!!))
        Logd(TAG+"PRINT_EncryptTo",Base64.encodeToString(encodedBytes, Base64.DEFAULT)
        )
        return Base64.encodeToString(encodedBytes, Base64.DEFAULT)
    }


    @Throws(Exception::class)
    fun decrypt(encrypted_str: String): String {
        val encrypted_byte: ByteArray = Base64.decode(encrypted_str, Base64.DEFAULT)
        val c = Cipher.getInstance(AES_MODE, "BC")
        c.init(Cipher.DECRYPT_MODE, getSecretKey())
        val decrypted_Str = String(c.doFinal(encrypted_byte))
        Logd(TAG+"PRINT_DecryptFrom", encrypted_str)
        Logd(TAG+"PRINT_DecryptTo", decrypted_Str)
        return decrypted_Str
    }
}