package jmh

import java.util.concurrent.TimeUnit
import org.openjdk.jmh.annotations._
import rsa.benchmark.{BenchmarkUtil, RSAUtil}


@BenchmarkMode(Array(Mode.All))
@Fork(1)
@Warmup(iterations = 3)
@Measurement(iterations = 5)
@Timeout(time = 60, timeUnit = TimeUnit.MINUTES)
@State(Scope.Benchmark)
class JMHBenchmark {

  val keySize = 16384
  val keyPair = BenchmarkUtil.generateKeyPair(keySize)
  val publicKey = keyPair.publicKey
  val privateKey = keyPair.privateKey

  var data_1k_1 = BenchmarkUtil.randomAscii(1024).getBytes()
  var data_1k_1_encrypt = RSAUtil.encryptLargeData(data_1k_1, keySize, publicKey)
  val data_1k_1024 = for (_ <- 1 to 1024) yield { BenchmarkUtil.randomAscii(1024).getBytes() }
  val data_1M_1 = BenchmarkUtil.randomAscii(1024 * 1024).getBytes() :: Nil
  val data_1k_1024_encrypt = data_1k_1024.map(RSAUtil.encryptLargeData(_, keySize, publicKey))
  val data_1M_1_encrypt = data_1M_1.map(RSAUtil.encryptLargeData(_, keySize, publicKey))


  @Setup(Level.Invocation)
  def setupInvocation() = {
    data_1k_1 = BenchmarkUtil.randomAscii(1024).getBytes()
    data_1k_1_encrypt = RSAUtil.encryptLargeData(data_1k_1, keySize, publicKey)
  }

  @JMHBenchmark
  @Warmup(iterations = 10)
  @Measurement(iterations = 1000)
  def encrypt_1k_1() = {
    RSAUtil.encryptLargeData(data_1k_1, keySize, publicKey)
  }

  @JMHBenchmark
  def encrypt_1k_1024() = {
    data_1k_1024.map(RSAUtil.encryptLargeData(_, keySize, publicKey))
  }

  @JMHBenchmark
  def encrypt_1M_1024() = {
    data_1M_1.map(RSAUtil.encryptLargeData(_, keySize, publicKey))
  }

  @JMHBenchmark
  def decrypt_1k_1024() = {
    data_1k_1024_encrypt.map(RSAUtil.decryptLargeData(_, keySize, privateKey))
  }

  @JMHBenchmark
  def decrypt_1M_1024() = {
    data_1M_1_encrypt.map(RSAUtil.decryptLargeData(_, keySize, privateKey))
  }

  @JMHBenchmark
  @Warmup(iterations = 10)
  @Measurement(iterations = 1000)
  def decrypt_1k_1() = {
    RSAUtil.decryptLargeData(data_1k_1_encrypt, keySize, privateKey)
  }

}
