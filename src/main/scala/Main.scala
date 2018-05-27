import java.nio.file.{Files, Paths}

object Main extends App {

  val keySize = 16384
  val testPath = "/tmp"
  case class Result(input: Array[Byte] = Array(), encrypt: Array[Byte] = Array(), encryptMs: Long = 0, decrypt: Array[Byte] = Array(), decryptMs: Long = 0)

  val keyPair = Benchmark.generateKeyPair(keySize)
  val publicKey = keyPair.publicKey
  val privateKey = keyPair.privateKey


  // small data
  val start = System.currentTimeMillis()
  val secureText = RSAUtil.encryption(publicKey, "test".getBytes)
  val plainText = RSAUtil.decryption(privateKey, secureText)
  val end = System.currentTimeMillis()
  println(new String(plainText) + ": " + (end - start) + "ms")


  // 1k Byte * 1024 data
  benchmarkRSA("1k_1024", 1024, 1024)

  // 1M Byte * 1 data
  benchmarkRSA("1M_1", 1024 * 1024, 1)


  def benchmarkRSA(dataName: String, dataSize: Int, dataCount: Int): Unit = {

    // create data
    val inputData: Seq[Result] = for (i <- 1 to dataCount) yield {
      val data = Benchmark.randomAscii(dataSize).getBytes()
      Files.write(Paths.get(s"$testPath/${dataName}_input_%04d.txt".format(i)), data)
      Result(input = data)
    }

    // encrypt
    val encryptData: Seq[Result] = inputData.zipWithIndex.map{case (data: Result, i: Int) =>
      val start = System.currentTimeMillis()
      val res = RSAUtil.encryptLargeData(data.input, keySize, publicKey)
      val end = System.currentTimeMillis()
      Files.write(Paths.get(s"$testPath/${dataName}_encrypt_%04d.txt".format(i)), res)
      data.copy(encrypt = res, encryptMs = end - start)
    }

    // decrypt
    val resultData: Seq[Result] = encryptData.zipWithIndex.map{case (data: Result, i: Int) =>
      val start = System.currentTimeMillis()
      val res = RSAUtil.decryptLargeData(data.encrypt, keySize, privateKey)
      val end = System.currentTimeMillis()
      Files.write(Paths.get(s"$testPath/${dataName}_decrypt_%04d.txt".format(i)), res)
      data.copy(decrypt = res, decryptMs = end - start)
    }

    // result
    val (encryptMs, decryptMs) = resultData.foldLeft((0L, 0L))((t, e) => {
      if (!(e.input sameElements e.decrypt)) throw new RuntimeException("**** decrypt error ****")
      (t._1 + e.encryptMs, t._2 + e.decryptMs)
    })

    println(dataName)
    println(s"encrypt: $encryptMs ms, decrypt: $decryptMs ms")

  }

}
