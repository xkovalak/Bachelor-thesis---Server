import java.io.ObjectInputStream
import java.io.ObjectOutputStream
import java.net.InetAddress
import java.net.NetworkInterface
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import java.util.*
import javax.net.ssl.*


class HttpsServer(
    private val port: Int,
    private val password: CharArray,
    private val privateKey: PrivateKey,
    private val certificate: Certificate,
) {

    private lateinit var serverSocket: SSLServerSocket
    private var isServerOn: Boolean = false

    init {
        println()
        println(InetAddress.getLocalHost().hostAddress)
        println()
        //NetworkInterface.networkInterfaces().forEach {
        //    displayInterfaceInformation(it)
        //}
    }

    fun start() {
        val context = createSSLContext()

        val serverSocketFactory = context.serverSocketFactory
        serverSocket = serverSocketFactory.createServerSocket(port) as SSLServerSocket

        isServerOn = true

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

            println("Local certificates: ${socket.session.localCertificates.first().encoded}")
            //println("Peer certificates: ${socket.session.peerCertificates}")

            var certificateChain: Array<X509Certificate>
            var input: ObjectInputStream? = null

            try {
                input = ObjectInputStream(socket.inputStream)
                certificateChain = input.readObject() as Array<X509Certificate>

            } catch (e: Exception) {
                println("Getting certificate chain failed")
                println(e)
                socket.close()
                input?.close()
                continue
            }

            try {
                validateCertificateChain(certificateChain)
            } catch (e: Exception) {
                println("Certificate chain is not valid!")
                println(e)
                socket.close()
                input.close()
                continue
            }

            val key = generateKey("DESede", 168)
            println("KEY: ${String(key.encoded)}")
            val encryptedKey = encrypt(certificateChain.first().publicKey, "RSA", key.encoded)
            println("Encrypted key: ${String(encryptedKey)}")

            val out = ObjectOutputStream(socket.outputStream)
            out.writeObject(encryptedKey)

            out.close()
            socket.close()
        }
    }

    private fun createSSLContext(): SSLContext {
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

    private fun displayInterfaceInformation(netInterface: NetworkInterface) {
        if (!netInterface.inetAddresses.hasMoreElements()) {
            return
        }

        println("Display name: ${netInterface.displayName}")
        println("Name: ${netInterface.name}")
        val inetAddresses = netInterface.inetAddresses
        for (inetAddress in Collections.list(inetAddresses)) {
            println("InetAddress: $inetAddress")
        }
        println()
    }

    companion object {
        private const val ALIAS = "key_store_alias"
    }
}