import kotlinx.serialization.Serializable

@Serializable
data class RevokedCertificateStatus(
    val status: Status,
    val reason: Reason,
    val comment: String?,
    val expires: String?,
)

enum class Status {
    REVOKED, SUSPENDED,
}

enum class Reason {
    UNSPECIFIED, KEY_COMPROMISE, CA_COMPROMISE, SUPERSEDED, SOFTWARE_FLAW,
}