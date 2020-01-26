package com.seeker.encryptioninkotlin

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.widget.Toast
import com.seeker.encryptioninkotlin.encryption.Encryption
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
            if(! message.text.toString().equals("")){
                plainString = message.text.toString()
                encryptedString = encryption.encrypt(plainString)!!
                result.text = encryptedString
            }else{
                Toast.makeText(this,"Type message",Toast.LENGTH_SHORT).show()
            }
        }

        decrypt.setOnClickListener {
            if(encryptedString!=null){
                val decryptedString: String = encryption.decrypt(encryptedString!!).toString()
                result.text = decryptedString
            }else{
                Toast.makeText(this,"Encrypt first",Toast.LENGTH_SHORT).show()
            }
        }
    }


}
