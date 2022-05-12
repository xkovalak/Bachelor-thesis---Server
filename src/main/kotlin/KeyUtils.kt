import java.io.File
import java.security.Key
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.spec.PKCS8EncodedKeySpec
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

fun loadPrivateKey(keyFile: File, algorithm: String): PrivateKey {
    val keyFactory = KeyFactory.getInstance(algorithm)

    val fileContent = keyFile.readText()
        .substringAfter("-----BEGIN PRIVATE KEY-----")
        .replace(System.lineSeparator(), "")
        .substringBefore("-----END PRIVATE KEY-----")
        .toByteArray()

    val keySpec = PKCS8EncodedKeySpec(Base64.getMimeDecoder().decode(fileContent))

    return keyFactory.generatePrivate(keySpec)
}

fun generateKey(algorithm: String, size: Int): SecretKey {
    val generator = KeyGenerator.getInstance(algorithm)
    generator.init(size)

    return generator.generateKey()
}

fun encrypt(key: Key, algorithm: String, message: ByteArray): ByteArray {
    val cipher = Cipher.getInstance(algorithm)
    cipher.init(Cipher.ENCRYPT_MODE, key)
    val encryptedMessage = cipher.doFinal(message)
    println("Encrypted message: ${Base64.getEncoder().encodeToString(encryptedMessage)}")

    return encryptedMessage
}