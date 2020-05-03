# Encryption 

You can store secrets in Preferences after encrypting them.

But what about the keys used to encrypt the data? A general rule is you should not use any hardcoded keys because a hacker can easily decompile your code and obtain the key, thereby rendering the encryption useless. You need a key management framework, and that’s what the Android KeyStore API is designed for.

KeyStore provides two functions:
1) Randomly generates keys; and
2) Securely stores the keys

With these, storing secrets becomes easy. All you have to do is:
- Generate a random key when the app runs the first time;
- When you want to store a secret, retrieve the key from KeyStore, encrypt the data with it, and then store the encrypted data in Preferences.
- When you want to read a secret, read the encrypted data from Preferences, get the key from KeyStore and then use the key to decrypt the data.

Your key is randomly generated and securely managed by KeyStore and only your code can read it.

### Followings are the options to generate and store keys safely depending on Android API level.
## <b>API Level < 18:</b> 
Android Keystore not present. Request a password to the user, derive an encryption key from the password, The drawback is that you need to prompt for the password when application starts. The encryption key it is not stored in the device. It is calculated each time when the application is started using the password

## <b>API Level >=18 <23:</b> 
Android Keystore available without AES support. Generate a random AES key using the default cryptographic provider (not using AndroidKeystore). 
### Key Generation
- Generate a pair of RSA keys
- Generate a random AES key
- Encrypt the AES key using the RSA public key
- Store the encrypted AES key in Preferences
### Encrypting and Storing the data
- Retrieve the encrypted AES key from Preferences
- Decrypt the above to obtain the AES key using the private RSA key
- Encrypt the data using the AES key
### Retrieving and decrypting the data
- Retrieve the encrypted AES key from Preferences
- Decrypt the above to obtain the AES key using the private RSA key
- Decrypt the data using the AES key


## <b>API Level >=23:</b> 
Android Keystore available with AES support. Generate a random AES key using into Android Keystore. You can use it directly.
### Generating the key
```
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

```

Where, ```AES_MODE = "AES/GCM/NoPadding"```   

> Do not use "AES" or "AES/ECB/PKCS7Padding" Since, ECB is insecure as it does not output unique encryptions when given duplicate data. We have used GCM Since, GCM provides both privacy and integrity 

### Getting the key
```
@Throws(Exception::class)
    fun getSecretKey(): Key? {
        return keyStore!!.getKey(KEY_ALIAS, null)
    }
```

### Encrypting the data
```
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
```

Where, ```FIXED_IV``` is Initial Vector. it’s a cryptographic feature that injects randomness to make it more secure. The important part is that the IV you use in the encryption must be the same one you use in the decryption.

> @RequiresApi (K) required and wont affect the module since we have check on method calling`

### Decrypting the data
```
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
```







