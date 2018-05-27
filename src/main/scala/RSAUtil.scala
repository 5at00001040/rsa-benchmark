import java.security.{KeyFactory, KeyPairGenerator}
import java.security.interfaces.{RSAPrivateKey, RSAPublicKey}
import java.security.spec.{PKCS8EncodedKeySpec, X509EncodedKeySpec}
import java.util.Base64

import javax.crypto.Cipher

case class RSAKeyPair(publicKey: RSAPublicKey, privateKey: RSAPrivateKey)

object RSAUtil {

  def encryption(publicKey: RSAPublicKey, plainData: Array[Byte]): Array[Byte] = {
    val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
    cipher.init(Cipher.ENCRYPT_MODE, publicKey)
    cipher.doFinal(plainData)
  }

  def decryption(privateKey: RSAPrivateKey, secureData: Array[Byte]): Array[Byte] = {
    val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
    cipher.init(Cipher.DECRYPT_MODE, privateKey)
    cipher.doFinal(secureData)
  }

  def generateKeyPair(keySize: Int) = {
    val keygen = KeyPairGenerator.getInstance("RSA")
    keygen.initialize(16384)

    val keyPair = keygen.generateKeyPair
    val publicKey = keyPair.getPublic.asInstanceOf[RSAPublicKey]
    val privateKey = keyPair.getPrivate.asInstanceOf[RSAPrivateKey]

    RSAKeyPair(publicKey, privateKey)
  }


  def encodePublicKey(key: RSAPublicKey): String = {
    Base64.getEncoder.encodeToString(key.getEncoded)
  }

  def encodePrivateKey(key: RSAPrivateKey): String = {
    Base64.getEncoder.encodeToString(key.getEncoded)
  }

  def decodePublicKey(keyStr: String): RSAPublicKey = {
    val keyFactory = KeyFactory.getInstance("RSA")
    val bytes = Base64.getDecoder.decode(keyStr)
    val spec = new X509EncodedKeySpec(bytes)
    keyFactory.generatePublic(spec).asInstanceOf[RSAPublicKey]
  }

  def decodePrivateKey(keyStr: String): RSAPrivateKey = {
    val keyFactory = KeyFactory.getInstance("RSA")
    val bytes = Base64.getDecoder.decode(keyStr)
    val spec = new PKCS8EncodedKeySpec(bytes)
    keyFactory.generatePrivate(spec).asInstanceOf[RSAPrivateKey]
  }

  def encryptLargeData(data: Array[Byte], keySize: Int, publicKey: RSAPublicKey): Array[Byte] = {

    val splitSize = (keySize - 88) / 8

    def encryptLarge(head: Array[Byte], tail: Array[Byte]): Array[Byte] = {
      if (tail.length <= 0) {
        head
      } else {
        val sp = tail.splitAt(splitSize)
        val en = RSAUtil.encryption(publicKey, sp._1)
        encryptLarge(head ++ en, sp._2)
      }
    }

    val split = data.splitAt(splitSize)
    encryptLarge(RSAUtil.encryption(publicKey, split._1), split._2)
  }

  def decryptLargeData(data: Array[Byte], keySize: Int, privateKey: RSAPrivateKey): Array[Byte] = {

    val splitSize = keySize / 8

    def decryptLarge(head: Array[Byte], tail: Array[Byte]): Array[Byte] = {
      if (tail.length <= 0) {
        head
      } else {
        val sp = tail.splitAt(splitSize)
        val en = RSAUtil.decryption(privateKey, sp._1)
        decryptLarge(head ++ en, sp._2)
      }
    }

    val split = data.splitAt(splitSize)
    decryptLarge(RSAUtil.decryption(privateKey, split._1), split._2)
  }

}
