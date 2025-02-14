Creating a secure communication system using Java that integrates blockchain, Tor technology, and encryption is a complex task. Below is a simplified example that demonstrates how to create a basic client-server communication system with encryption. This example does not fully implement blockchain or Tor but provides a foundation that you can build upon.

Prerequisites:
Java Development Kit (JDK)

BouncyCastle library for encryption (you can add it via Maven or download the JAR).

Tor (you can use the Tor network by routing traffic through a local Tor proxy).

## Step 1: Add BouncyCastle to your project
If you're using Maven, add the following dependency to your pom.xml:

```xml
<dependency>
    <groupId>org.bouncycastle</groupId>
    <artifactId>bcprov-jdk15on</artifactId>
    <version>1.70</version>
</dependency>
```
Run HTML
## Step 2: Create the Server
```java
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Security;

public class SecureServer {

    private static final String ALGORITHM = "AES";
    private static final byte[] KEY = "MySuperSecretKey".getBytes();

    public static void main(String[] args) {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        try (ServerSocket serverSocket = new ServerSocket(5000)) {
            System.out.println("Server is listening on port 5000...");

            while (true) {
                Socket socket = serverSocket.accept();
                System.out.println("New client connected");

                new ServerThread(socket).start();
            }
        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }

    private static class ServerThread extends Thread {
        private Socket socket;

        public ServerThread(Socket socket) {
            this.socket = socket;
        }

        public void run() {
            try (InputStream input = socket.getInputStream();
                 OutputStream output = socket.getOutputStream();
                 BufferedReader reader = new BufferedReader(new InputStreamReader(input));
                 PrintWriter writer = new PrintWriter(output, true)) {

                String encryptedMessage = reader.readLine();
                String decryptedMessage = decrypt(encryptedMessage);
                System.out.println("Received: " + decryptedMessage);

                String response = "Hello from server";
                String encryptedResponse = encrypt(response);
                writer.println(encryptedResponse);

            } catch (Exception ex) {
                ex.printStackTrace();
            }
        }

        private String encrypt(String data) throws Exception {
            SecretKeySpec secretKey = new SecretKeySpec(KEY, ALGORITHM);
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptedBytes = cipher.doFinal(data.getBytes());
            return new String(encryptedBytes);
        }

        private String decrypt(String encryptedData) throws Exception {
            SecretKeySpec secretKey = new SecretKeySpec(KEY, ALGORITHM);
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] decryptedBytes = cipher.doFinal(encryptedData.getBytes());
            return new String(decryptedBytes);
        }
    }
}
```
## Step 3: Create the Client
```java
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.security.Security;

public class SecureClient {

    private static final String ALGORITHM = "AES";
    private static final byte[] KEY = "MySuperSecretKey".getBytes();

    public static void main(String[] args) {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        String hostname = "localhost";
        int port = 5000;

        try (Socket socket = new Socket(hostname, port)) {
            OutputStream output = socket.getOutputStream();
            PrintWriter writer = new PrintWriter(output, true);

            InputStream input = socket.getInputStream();
            BufferedReader reader = new BufferedReader(new InputStreamReader(input));

            String message = "Hello from client";
            String encryptedMessage = encrypt(message);
            writer.println(encryptedMessage);

            String encryptedResponse = reader.readLine();
            String decryptedResponse = decrypt(encryptedResponse);
            System.out.println("Server response: " + decryptedResponse);

        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    private static String encrypt(String data) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(KEY, ALGORITHM);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(data.getBytes());
        return new String(encryptedBytes);
    }

    private static String decrypt(String encryptedData) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(KEY, ALGORITHM);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedBytes = cipher.doFinal(encryptedData.getBytes());
        return new String(decryptedBytes);
    }
}
```
## Step 4: Running the Server and Client
Start the server by running SecureServer.

Start the client by running SecureClient.

## Step 5: Integrating Tor (Optional)
To route traffic through Tor, you can use a local Tor proxy. You would need to configure your client to connect to the Tor network by setting up a SOCKS proxy. This can be done using the java.net.Proxy class.

## Step 6: Blockchain Integration (Optional)
To integrate blockchain, you could use a blockchain library like Web3j for Ethereum or BitcoinJ for Bitcoin. You would need to create a smart contract or use the blockchain to store and verify messages.

### Security Considerations
- **Key Management**: The key used in this example is hardcoded, which is not secure. Use a secure key management system.

- **Tor Integration**: Properly configure Tor to ensure anonymity.

- **Blockchain**: Ensure that the blockchain network is secure and that smart contracts are audited.

This example provides a basic framework. For a production-level system, you would need to implement additional security measures, error handling, and possibly integrate with a blockchain network and Tor more deeply.
