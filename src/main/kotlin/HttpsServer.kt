import kotlinx.serialization.json.Json
import java.io.ObjectInputStream
import java.io.ObjectOutputStream
import java.math.BigInteger
import java.net.InetAddress
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import java.util.*
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory


class HttpsServer(
    private val port: Int,
    private val password: CharArray,
    private val privateKey: PrivateKey,
    private val certificate: Certificate,
) {

    private lateinit var serverSocket: SSLServerSocket
    private var isServerOn: Boolean = false

    fun start() {
        val context = createSSLContext()

        val serverSocketFactory = context.serverSocketFactory
        serverSocket = serverSocketFactory.createServerSocket(port) as SSLServerSocket

        isServerOn = true

        println("Server started. For stopping type \"stop\"")
        println()
        println("Server IP address: " + InetAddress.getLocalHost().hostAddress)
        println()

        while (isServerOn) {
            println("Waiting for socket")
            val socket = serverSocket.accept() as SSLSocket
            println("Socket accepted, starting handshake")

            try {
                socket.startHandshake()
            } catch (e: Exception) {
                println("Handshake failed")
                println(e)
                socket.close()
                continue
            }

            var certificateChain: Array<X509Certificate>
            var input: ObjectInputStream? = null

            val attestationChallenge = BigInteger(256, Random()).toByteArray()
            val out = ObjectOutputStream(socket.outputStream)

            try {

                out.writeObject(attestationChallenge)

                input = ObjectInputStream(socket.inputStream)
                certificateChain = input.readObject() as Array<X509Certificate>

            } catch (e: Exception) {
                println("Getting certificate chain failed!")
                println(e)
                val result = ServerResult(true, "Getting certificate chain failed!")
                out.writeObject(Json.encodeToString(ServerResult.serializer(), result))
                out.close()
                socket.close()
                input?.close()
                continue
            }

            try {
                validateCertificateChain(certificateChain, attestationChallenge)
            } catch (e: Exception) {
                println("Certificate chain is not valid!")
                println(e)
                val result = ServerResult(true, e.message ?: "Certificate chain is not valid!")
                out.writeObject(Json.encodeToString(ServerResult.serializer(), result))
                out.close()
                socket.close()
                input.close()
                continue
            }

            val key = generateKey("DESede", 168)
            println("KEY: ${key.encoded.toHexString()}")
            val encryptedKey = encrypt(certificateChain.first().publicKey, "RSA", key.encoded)
            println("Encrypted key: ${encryptedKey.toHexString()}")

            val result = ServerResult(false, "Success", encryptedKey)
            out.writeObject(Json.encodeToString(ServerResult.serializer(), result))

            out.close()
            socket.close()
        }
    }

    private fun createSSLContext(): SSLContext {
        println("Creating SSL context...")

        val keyStore = KeyStore.getInstance(KeyStore.getDefaultType())
        keyStore.load(null)
        keyStore.setKeyEntry(ALIAS, privateKey, password, arrayOf(certificate))

        val keyManager = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
        keyManager.init(keyStore, password)

        val trustManager =
            TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        trustManager.init(keyStore)

        val context = SSLContext.getInstance("TLSv1.2")
        context.init(keyManager.keyManagers, trustManager.trustManagers, null)

        return context
    }

    fun stop() {
        isServerOn = false
    }

    companion object {
        private const val ALIAS = "key_store_alias"
    }
}