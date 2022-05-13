import ASN1Parser.Companion.KEY_DESCRIPTION_OID
import com.google.gson.JsonParser
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Sequence
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

fun validateCertificateChain(certificates: Array<X509Certificate>, attestationChallenge: ByteArray) {
    println("Validating certificate chain")

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
        throw SecurityException("Device does not contain correct root certificate!")
    }

    checkCertificateDataScheme(certificates.first(), attestationChallenge)
}

private fun checkCertificateDataScheme(certificate: X509Certificate, attestationChallenge: ByteArray) {
    val extensionData = extractAttestationSequence(certificate)
    val parsedData = ASN1Parser(extensionData)

    if (!parsedData.attestationChallenge.contentEquals(attestationChallenge)) {
        throw SecurityException("Attestation challenge is not correct")
    }

    if (parsedData.attestationSecurityLevel == SecurityLevel.SOFTWARE) {
        throw SecurityException("Attestation security level is only software!")
    }
}

private fun extractAttestationSequence(attestationCert: X509Certificate): ASN1Sequence {
    val attestationExtensionBytes: ByteArray = attestationCert.getExtensionValue(KEY_DESCRIPTION_OID)
    require(attestationExtensionBytes.isNotEmpty()) { "Couldn't find the keystore attestation extension data." }

    var decodedSequence: ASN1Sequence
    ASN1InputStream(attestationExtensionBytes).use { asn1InputStream ->
        val derSequenceBytes = (asn1InputStream.readObject() as ASN1OctetString).octets
        ASN1InputStream(derSequenceBytes).use { seqInputStream ->
            decodedSequence = seqInputStream.readObject() as ASN1Sequence
        }
    }
    return decodedSequence
}

private const val ROOT_CERTIFICATE = "certs/google_root_cert.pem"