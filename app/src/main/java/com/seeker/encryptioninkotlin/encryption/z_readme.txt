
        /*TESTING PURPOSE*/


        /*Create object of encryption class*/
        var encryption = Encryption(this)

        /*Create demo string for testing purpose*/
        var demoString = "CODE IS WRITTEN BY PRATIM"

        /*Encrypt string and see resultin Log*/
        var encryptedString = encryption.encrypt(demoString)

        /*Decrypt string after 2 second and see resultin Log*/
        Handler().postDelayed({
            //val decrypted_byte: ByteArray = Base64.decode(encryptedString, Base64.DEFAULT)
            val decryptedString: String = encryption.decrypt(encryptedString).toString()
            Logd(TAG!!,decryptedString)
        }, 2000)






DESCRIPTION :
    Symmetric key generation and storage in the Android KeyStore is supported from Android 6.0 (API Level 23) onwards.
    Asymmetric key generation and storage in the Android KeyStore is supported from Android 4.3 (API Level 18) onwards.

    Following are the steps for this module
    1) Generate RSA key pair
    2) Generate AES using randomization
    3) Encrypt AES with RSA key pair
    4) Encrypt again with Base64 encode
    5) Store into Shared Pref
        Here, Even if intruder fetch the shared pref values, our AES key is safe. since, it is encrypted with RSA key pair
    While Encryption:
    6) Fetch Base64 encrypted AES from Shared Pref and decrypt
    7) decrypt again with RSA key pair to get actual AES key
    8) now, decrypt data with actual AES key.


QUESTIONS:
    1) why cant encrypt with RSA? Why we need to Encrypt/Decrypt AES key and then ecrypt with AES key?
    Ans: RSA is designed for Client-Server architecture since it has Asymmetric pattern and the key size of RSA key is almost Ten times of AES.
    Hence it take more time that AES to encrypt and decrypt data. Imagine when you need to encrypt large amount of data in SQLite db or need to encrypt whole db using RSA. It will take lot more time that AES.
    Also, in the matter of processing, AES is much faster that RSA due to its small key size.

    2) Why should generate AES with randomization?
    Ans: It is very easy to reverse engineering android app. If given value for AES is compromised then it is easy to generate AES key.



