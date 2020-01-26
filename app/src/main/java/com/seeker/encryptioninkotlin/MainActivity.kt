package com.seeker.encryptioninkotlin

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.os.Handler
import android.util.Base64
import com.ft.ecom.encryption.Encryption
import com.ft.ecom.encryption.Logd
import kotlinx.android.synthetic.main.activity_main.*

class MainActivity : AppCompatActivity() {

    val TAG=MainActivity::class.simpleName
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        var encryptedString:String? = null
        var plainString:String
        /*Create object of encryption class*/
        var encryption = Encryption(this)

        encrypt.setOnClickListener {
            plainString = message.text.toString()
            encryptedString = encryption.encrypt(plainString)!!
            result.text = encryptedString
        }

        decrypt.setOnClickListener {
            val decryptedString: String = encryption.decrypt(encryptedString!!).toString()
            result.text = decryptedString

        }
    }


}
