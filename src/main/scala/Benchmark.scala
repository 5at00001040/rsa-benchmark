import scala.util.Random

object Benchmark {

  def generateKeyPair(keySize: Int) = {
    val keyPair = RSAUtil.generateKeyPair(keySize)
    println("public:" + RSAUtil.encodePublicKey(keyPair.publicKey))
    println("private:" + RSAUtil.encodePrivateKey(keyPair.privateKey))
    keyPair
  }

  def randomAscii(length: Int) = {
    val chars = for (_ <- 1 to length) yield {
      Random.nextPrintableChar
    }
    chars.map(_.toString).mkString
  }


  System.currentTimeMillis()

}

