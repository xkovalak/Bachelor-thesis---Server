import java.io.File
import java.security.KeyFactory
import java.security.cert.CertificateFactory
import java.security.spec.PKCS8EncodedKeySpec
import java.util.*

fun main() {
    println()

    val cert = loadCertificate(File("certs/server_cert.pem"))

    val privateKey = loadPrivateKey(File("certs/privateKey.pkcs8"), "RSA")

    HttpsServer(7879, "password".toCharArray(), privateKey, cert).start()
}