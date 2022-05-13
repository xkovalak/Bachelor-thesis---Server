import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1Enumerated
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Sequence

class ASN1Parser(extensionData: ASN1Sequence) {

    var attestationVersion: Int = 0
    var attestationSecurityLevel: SecurityLevel
    var keymasterVersion: Int = 0
    var keymasterSecurityLevel: SecurityLevel
    var attestationChallenge: ByteArray
    var uniqueId: ByteArray

    init {
        attestationVersion = getIntegerFromAsn1(extensionData.getObjectAt(ATTESTATION_VERSION_INDEX))
        attestationSecurityLevel = securityLevelToEnum(
            getIntegerFromAsn1(
                extensionData.getObjectAt(ATTESTATION_SECURITY_LEVEL_INDEX)
            )
        )
        keymasterVersion = getIntegerFromAsn1(extensionData.getObjectAt(KEYMASTER_VERSION_INDEX))
        keymasterSecurityLevel = securityLevelToEnum(
            getIntegerFromAsn1(
                extensionData.getObjectAt(KEYMASTER_SECURITY_LEVEL_INDEX)
            )
        )
        attestationChallenge = (extensionData.getObjectAt(ATTESTATION_CHALLENGE_INDEX) as ASN1OctetString).octets
        uniqueId = (extensionData.getObjectAt(UNIQUE_ID_INDEX) as ASN1OctetString).octets
    }

    private fun securityLevelToEnum(securityLevel: Int): SecurityLevel {
        return when (securityLevel) {
            KM_SECURITY_LEVEL_SOFTWARE -> SecurityLevel.SOFTWARE
            KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> SecurityLevel.TRUSTED_ENVIRONMENT
            KM_SECURITY_LEVEL_STRONG_BOX -> SecurityLevel.STRONG_BOX
            else -> throw IllegalArgumentException("Invalid security level.")
        }
    }

    private fun getIntegerFromAsn1(asn1Value: ASN1Encodable): Int = when (asn1Value) {
        is ASN1Integer -> asn1Value.value.intValueExact()
        is ASN1Enumerated -> asn1Value.value.intValueExact()
        else -> throw IllegalArgumentException("Integer value expected; found " + asn1Value.javaClass.name + " instead.")
    }

    companion object {
        const val KEY_DESCRIPTION_OID = "1.3.6.1.4.1.11129.2.1.17"
        const val ATTESTATION_VERSION_INDEX = 0
        const val ATTESTATION_SECURITY_LEVEL_INDEX = 1
        const val KEYMASTER_VERSION_INDEX = 2
        const val KEYMASTER_SECURITY_LEVEL_INDEX = 3
        const val ATTESTATION_CHALLENGE_INDEX = 4
        const val UNIQUE_ID_INDEX = 5
        const val KM_SECURITY_LEVEL_SOFTWARE = 0
        const val KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT = 1
        const val KM_SECURITY_LEVEL_STRONG_BOX = 2
    }
}