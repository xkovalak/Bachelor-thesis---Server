import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import java.io.File
import java.util.*

fun main() {
    println()
    println("Starting server...")

    val cert = loadCertificate(File("certs/server_cert.pem"))

    val privateKey = loadPrivateKey(File("certs/privateKey.pkcs8"), "RSA")

    val server = HttpsServer(7879, "password".toCharArray(), privateKey, cert)

    val serverJob = CoroutineScope(Dispatchers.IO).launch {
        server.start()
    }

    val scanner = Scanner(System.`in`)
    while (true) {
        val input = scanner.nextLine()
        if (input == "stop") {
            println("Stopping server...")
            server.stop()
            serverJob.cancel()
            break
        }
    }
}