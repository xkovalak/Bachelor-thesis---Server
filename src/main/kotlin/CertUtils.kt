import com.google.gson.JsonParser
import java.io.File
import java.io.InputStreamReader
import java.net.URL
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.*

private val certFactory = CertificateFactory.getInstance("X.509")

fun loadCertificate(certFile: File): X509Certificate {
    val certContent = certFile.readText()

    return certFactory.generateCertificate(certContent.byteInputStream(Charsets.UTF_8)) as X509Certificate
}

fun validateCertificateChain(certificates: Array<X509Certificate>) {
    val inputStream = URL("https://android.googleapis.com/attestation/status").openStream()
    val entries = JsonParser().parse(InputStreamReader(inputStream)).asJsonObject
        .getAsJsonObject("entries")

    var parent = certificates.last()
    for (i in certificates.lastIndex downTo 0) {
        val cert = certificates[i]
        cert.checkValidity()
        cert.verify(parent.publicKey)

        // check revoked status
        if (entries.has(cert.serialNumber.toString(16))) {
            throw SecurityException("Certificate has been revoked! Certificate serial number: ${cert.serialNumber}")
        }

        parent = cert
    }

    // Check google root certificate
    val rootCertificate = loadCertificate(File(ROOT_CERTIFICATE))

    if (!Arrays.equals(rootCertificate.publicKey.encoded, certificates.last().publicKey.encoded)) {
        println("Does not contain root certificate!")
    }
}

private const val ROOT_CERTIFICATE = "certs/google_root_cert.pem"