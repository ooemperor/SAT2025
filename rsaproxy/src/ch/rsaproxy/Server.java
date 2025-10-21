/**
 * File for the implementation of Server in the rsaproxy
 *
 * @author: Michael Kaiser
 */
package ch.rsaproxy;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/**
 * class for the definition of a server
 */
public class Server {

    private ServerSocket clientServerSocket;
    private Socket serverSocket;

    private final String remoteAddress;
    private final int remotePort;
    private final int localClientPort;
    private final int localServerPort;

    private DataOutputStream clientOut;
    private DataInputStream remoteIn;
    private DataOutputStream remoteOut;

    private KeyPair keyPair;
    private PublicKey remotePubKey;

    private volatile boolean shutdown = false;
    private final ExecutorService threadpool;


    /**
     * Constructor of the server
     *
     * @param remoteAddress   the address on which the server should connect to
     * @param remotePort      the port used by the remote server
     * @param localClientPort the port for traffic to and from the local client
     * @param localServerPort the port used by this specific server to manage the server to server traffic.
     */
    public Server(String remoteAddress, int remotePort, int localClientPort, int localServerPort) {
        assert remoteAddress != null && !remoteAddress.isEmpty();
        assert remotePort > 0 && remotePort < 65535;
        assert localClientPort > 0 && localClientPort < 65535;
        assert localServerPort > 0 && localServerPort < 65535;

        this.remoteAddress = remoteAddress;
        this.remotePort = remotePort;

        this.localClientPort = localClientPort;
        this.localServerPort = localServerPort;

        this.threadpool = Executors.newCachedThreadPool();

        this.setupKeys();
        this.invariant();
    }

    /**
     * invariant method to check the consistency of the object
     */
    private void invariant() {
        assert remoteAddress != null && !remoteAddress.isEmpty();
        assert remotePort > 0 && remotePort < 65535;
        assert localClientPort > 0 && localClientPort < 65535;
        assert localServerPort > 0 && localServerPort < 65535;
    }

    /**
     * initialize the variables
     */
    private void init() {
        this.invariant();
        Boolean serverSocketSuccess = this.setupServerSocket();
    }

    /**
     * Sets up all the ServerSockets
     *
     * @return true if succesful
     */
    private boolean setupServerSocket() {
        this.invariant();
        this.log("Setting up ServerSockets");
        ServerSocket serverServerSocket;
        try {
            this.clientServerSocket = new ServerSocket(this.localClientPort);
            serverServerSocket = new ServerSocket(this.localServerPort);
        } catch (IOException e) {
            this.log("Could not setup server socket " + e);
            return false;
        }

        // try to connect to remote server
        try {
            this.log("Trying to connect to remote server: " + this.remoteAddress + ":" + this.remotePort);
            this.serverSocket = new Socket(this.remoteAddress, this.remotePort);
            // if we get here, then connection is good and have to start the keyexchange.
            this.streamSetup();
            this.sendPubkey();
            this.listenPubkey();

        } catch (IOException e) {
            this.log("Could not setup server socket " + e);
        }

        try {
            if (this.serverSocket == null) {
                this.log("Waiting for remote server to setup connection");
                // we don't have a connection to the remote server so we need to wait for it.
                this.serverSocket = serverServerSocket.accept();
                this.log("Connection established from remote server: " + this.remoteAddress + ":" + this.remotePort);
                this.streamSetup();
                this.listenPubkey();
                this.sendPubkey();
            }
        } catch (IOException e) {
            this.log("Could not accept server socket " + e);
            return false;
        }
        return true;
    }

    /**
     * set up the input and output stream to and from the remote server
     */
    private void streamSetup() throws IOException {
        this.remoteIn = new DataInputStream(this.serverSocket.getInputStream());
        this.remoteOut = new DataOutputStream(this.serverSocket.getOutputStream());
    }

    /**
     * Send own public key to the remote server
     *
     * @throws IOException when we cannot read what is coming from the remote server
     */
    private void sendPubkey() throws IOException {

        this.log("Sending Pubkey");
        this.remoteOut.writeUTF("START PUBKEY");
        this.remoteOut.write(this.getPublicKey().getEncoded());
        this.remoteOut.writeUTF("END PUBKEY");
        this.log("Finished sending Pubkey");
    }

    /**
     * listen for the remote server to transmit the pubkey
     *
     * @throws IOException when error in decoding occurs
     */
    private void listenPubkey() throws IOException {
        this.log("Listening for Pubkey");
        String msg1 = this.remoteIn.readUTF();
        if (!msg1.equals("START PUBKEY")) {
            this.log("Invalid first message while reading pubkey");
            return;
        }

        // here comes the pubkey
        byte[] msg2 = this.remoteIn.readNBytes(294);
        this.remotePubKey = this.readPublicKey(msg2);

        String msg3 = this.remoteIn.readUTF();
        if (!msg3.equals("END PUBKEY")) {
            this.log("Invalid last message while reading pubkey");
        }
        this.log("Finished reading Pubkey");
    }

    /**
     * Read a public key from a raw string
     *
     * @param rawKey the raw string that represents the public key
     * @return the PublicKeyObject
     * @throws IOException when error occurs in decoder
     */
    private PublicKey readPublicKey(byte[] rawKey) throws IOException {
        try {
            X509EncodedKeySpec spec = new X509EncodedKeySpec(rawKey);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(spec);
        } catch (NoSuchAlgorithmException algo) {
            this.log("RSA algorithm not found");
        } catch (InvalidKeySpecException key) {
            this.log("Invalid key spec");
        }
        return null;
    }

    /**
     * Shutdown the server
     */
    private void shutdown() {
        this.log("Shutting down...");
        this.threadpool.shutdown();
        this.shutdown = true;
        System.exit(0);
    }


    /**
     * Method to run the client
     */
    public void run() {
        this.log("Starting server on port " + this.localServerPort);
        this.init();
        this.log("Starting Client to Remote Server part of the server");

        Future<?> clientToRemote = this.threadpool.submit(this::clientToRemoteServer);
        Future<?> remoteToClient = this.threadpool.submit(this::remoteServerToClient);
        while (!this.shutdown) {
        } // we do nothing and loop
    }

    /**
     * process the traffic from the client to the remote server
     */
    private void clientToRemoteServer() {
        this.log("Waiting for connections on port " + this.localClientPort);
        try {
            Socket clientSocket = this.clientServerSocket.accept();
            this.log("Accepted connection on port " + this.localClientPort);
            DataInputStream clientIn = new DataInputStream(clientSocket.getInputStream());
            this.clientOut = new DataOutputStream(clientSocket.getOutputStream());

            String msg = "";

            while (!msg.equals("kill") && !this.shutdown) {
                try {
                    msg = clientIn.readUTF();
                    this.log("Local Client: " + msg);
                    String encrypted = this.encrypt(msg);
                    if (encrypted == null) {
                        encrypted = "";
                    }
                    this.remoteOut.writeUTF(encrypted);
                } catch (IOException e) {
                    this.log("Could not read from the client " + e);
                }
            }

            this.remoteOut.writeUTF("kill");
            // kill message received
            clientSocket.close();
            this.shutdown();

        } catch (IOException e) {
            this.log("Could not accept connection on port " + this.localClientPort);
        }
    }

    /**
     * process the traffic from the remote server to the client
     */
    private void remoteServerToClient() {
        try {
            String msg = "";

            while (!msg.equals("kill") && !this.shutdown) {
                try {
                    msg = this.remoteIn.readUTF();
                    this.log("Received encrypted message from remote server");
                    String decrypted = this.decrypt(msg);
                    this.log("Remote Server: " + decrypted);
                    if (decrypted == null) {
                        decrypted = "";
                    }
                    this.clientOut.writeUTF(decrypted);
                } catch (IOException e) {
                    this.log("Could not read from the remote Server" + e);
                }
            }
            this.clientOut.writeUTF("kill");
            // kill message received
            this.shutdown();

        } catch (IOException e) {
            this.log("Could not accept connection on port " + this.localClientPort);
        }
    }

    // crypto helper methods

    /**
     * Setup public and private keypair
     */
    private void setupKeys() {
        this.log("Setting up RSA keys");
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            this.keyPair = generator.generateKeyPair();
            this.log("Successfully setup RSA keys");

            this.log("Validating Pubkey Reader");
            byte[] pub = this.getPublicKey().getEncoded();
            PublicKey pubkeyCand = this.readPublicKey(pub);

            if (!pubkeyCand.equals(this.keyPair.getPublic())) {
                this.log("Invalid pubkey");
            }
        } catch (NoSuchAlgorithmException e) {
            this.log("RSA algorithm not available");
            this.log("Failed to setup RSA keys");
        } catch (IOException io) {
            this.log("Failed to validate RSA keys");
        }
    }

    /**
     * Helper method to generate a RSA cipher
     *
     * @return the RSA cipher
     */
    private Cipher getCipher() {
        try {
            return Cipher.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            this.log("RSA algorithm not available");
        } catch (NoSuchPaddingException pad) {
            this.log("Padding Exception: " + pad.getMessage());
        }
        return null;
    }

    /**
     * Helper method to encrypt a given text
     *
     * @param plainText the string to be encrypted
     * @return the encrypted value
     */
    private String encrypt(String plainText) {
        assert this.remoteAddress != null && !this.remoteAddress.isEmpty();
        try {
            Cipher encryptCipher = this.getCipher();
            assert encryptCipher != null;
            encryptCipher.init(Cipher.ENCRYPT_MODE, this.remotePubKey);

            byte[] plainTextBytes = plainText.getBytes();
            byte[] encryptedBytes = encryptCipher.doFinal(plainTextBytes);

            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (InvalidKeyException key) {
            this.log("Invalid key exception: " + key.getMessage());
        } catch (IllegalBlockSizeException block) {
            this.log("Invlaid Blocksize for encryption: " + block.getMessage());
        } catch (BadPaddingException badpad) {
            this.log("Bad padding exception: " + badpad.getMessage());
        }
        return null;
    }

    /**
     * helper method to decrypt the message received from the server
     *
     * @param encryptedText the encrypted text from the other proxy
     * @return the decrypted clear text
     */
    private String decrypt(String encryptedText) {
        try {
            Cipher decryptCipher = this.getCipher();
            assert decryptCipher != null;
            decryptCipher.init(Cipher.DECRYPT_MODE, this.getPrivateKey());

            byte[] encryptedTextBytes = Base64.getDecoder().decode(encryptedText);
            byte[] decryptedBytes = decryptCipher.doFinal(encryptedTextBytes);

            return new String(decryptedBytes);
        } catch (InvalidKeyException key) {
            this.log("Invalid key exception: " + key.getMessage());
        } catch (IllegalBlockSizeException block) {
            this.log("Invlaid Blocksize for encryption: " + block.getMessage());
        } catch (BadPaddingException badpad) {
            this.log("Bad padding exception: " + badpad.getMessage());
        }
        return null;
    }

    /**
     * Prints a log message
     *
     * @param message the log message to print
     */
    private void log(String message) {
        System.out.println(this.timestamp() + ": " + message);
    }

    /**
     * generate a formatted string of the current datetime
     *
     * @return the current timestamp used in logging
     */
    private String timestamp() {
        LocalDateTime now = LocalDateTime.now();

        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        return now.format(formatter);
    }

    // Getters and Setters

    private PrivateKey getPrivateKey() {
        return this.keyPair.getPrivate();
    }

    private PublicKey getPublicKey() {
        return this.keyPair.getPublic();
    }
}
