/**
 * File for the implementation of Server in the rsaproxy
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
import java.util.Base64;

/**
 * class for the definition of a server
 */
public class Server {

    private ServerSocket clientServerSocket;
    private ServerSocket serverServerSocket;
    private Socket serverSocket;

    private String remoteAddress;
    private int remotePort;
    private int localClientPort;
    private int localServerPort;

    private DataInputStream clientIn;
    private DataOutputStream clientOut;
    private DataInputStream remoteIn;
    private DataOutputStream remoteOut;

    private KeyPair keyPair;
    private PublicKey remotePubKey;


    /**
     * Constructor of the server
     * @param remoteAddress the address on which the server should connect to
     * @param remotePort the port used by the remote server
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
    private void init(){
        this.invariant();
        Boolean serverSocketSuccess = this.setupServerSocket();
    }

    /**
     * Sets up all the ServerSockets
     * @return true if succesful
     */
    private boolean setupServerSocket(){
        this.invariant();
        System.out.println("Setting up ServerSockets");
        try {
            this.clientServerSocket = new ServerSocket(this.localClientPort);
            this.serverServerSocket = new ServerSocket(this.localServerPort);
        }
        catch (IOException e) {
            System.out.println("Could not setup server socket " + e);
            return false;
        }

        // try to connect to remote server
        try {
            System.out.println("Trying to connect to remote server: " + this.remoteAddress + ":" + this.remotePort);
            this.serverSocket = new Socket(this.remoteAddress, this.remotePort);
            // if we get here, then connection is good and have to start the keyexchange.
            this.streamSetup();
            this.sendPubkey();

        }
        catch (IOException e) {
            System.out.println("Could not setup server socket " + e);
        }

        try {
            if (this.serverSocket == null) {
                System.out.println("Waiting for remote server to setup connection");
                // we don't have a connection to the remote server so we need to wait for it.
                this.serverSocket = this.serverServerSocket.accept();
                System.out.println("Connection established from remote server: " + this.remoteAddress + ":" + this.remotePort);
                this.streamSetup();
                this.listenPubkey();
            }
        }
        catch (IOException e) {
            System.out.println("Could not accept server socket " + e);
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
     * @throws IOException when we cannot read what is coming from the remote server
     */
    private void sendPubkey() throws IOException {

        System.out.println("Sending Pubkey");
        this.remoteOut.writeUTF("START PUBKEY");
        this.remoteOut.write(this.getPublicKey().getEncoded());
        this.remoteOut.writeUTF("END PUBKEY");
        System.out.println("Finished sending Pubkey");
    }

    /**
     * listen for the remote server to transmit the pubkey
     * @throws IOException when error in decoding occurs
     */
    private void listenPubkey() throws IOException {
        System.out.println("Listening for Pubkey");
        String msg1 =  this.remoteIn.readUTF();
        if (!msg1.equals("START PUBKEY")) {
            System.out.println("Invalid first message while reading pubkey");
            return;
        }

        // here comes the pubkey
        byte[] msg2 =  this.remoteIn.readNBytes(294);
        this.remotePubKey = this.readPublicKey(msg2);

        String msg3 =  this.remoteIn.readUTF();
        if (!msg3.equals("END PUBKEY")) {
            System.out.println("Invalid last message while reading pubkey");
        }
        System.out.println("Finished reading Pubkey");
    }

    /**
     * Read a public key from a raw string
     * @param rawKey the raw string that represents the public key
     * @return the PublicKeyObject
     * @throws IOException when error occurs in decoder
     */
    private PublicKey readPublicKey(byte[] rawKey) throws IOException {
        try {
            X509EncodedKeySpec spec = new X509EncodedKeySpec(rawKey);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(spec);
        }
        catch (NoSuchAlgorithmException algo) {
            System.out.println("RSA algorithm not found");
        }
        catch (InvalidKeySpecException key) {
            System.out.println("Invalid key spec");
        }
        return null;
    }

    /**
     * close all the sockets that may be open
     */
    private void closeAll() {

        try {
            this.clientServerSocket.close();
            this.serverServerSocket.close();
        }
        catch (IOException i){
            System.out.println("Could not close sockets");
        }
    }


    /**
     * Method to run the client
     * TODO: receiving data from client and sending to other server is done
     * TODO: need to implement receiving data from different stream at the same time
     */
    public void run(){
        System.out.println("Starting server on port " + this.localServerPort);
        this.init();
        System.out.println("Waiting for connections on port " + this.localClientPort);

        try {
            Socket clientSocket = this.clientServerSocket.accept();
            System.out.println("Accepted connection on port " + this.localClientPort);
            this.clientIn = new DataInputStream(clientSocket.getInputStream());

            String msg = "";

            while (!msg.equals("kill")) {
                try {
                    msg = this.clientIn.readUTF();
                    System.out.println(msg);
                    String encrypted = this.encrypt(msg);
                    this.remoteOut.writeUTF(encrypted);
                }
                catch (IOException e) {
                    System.out.println("Could not read from the client" + e);
                }
            }

            this.remoteOut.writeUTF("kill");
            // kill message received

            this.clientIn.close();
            this.clientOut.close();
            clientSocket.close();
            this.closeAll();

        }
        catch (IOException e) {
            System.out.println("Could not accept connection on port " + this.localClientPort);
        }
    }

    // crypto helper methods
    /**
     * Setup public and private keypair
     */
    private void setupKeys(){
        System.out.println("Setting up RSA keys");
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            this.keyPair = generator.generateKeyPair();
            System.out.println("Successfully setup RSA keys");

            System.out.println("Validating Pubkey Reader");
            byte[] pub = this.getPublicKey().getEncoded();
            PublicKey pubkeyCand = this.readPublicKey(pub);

            if (!pubkeyCand.equals(this.keyPair.getPublic())) {
                System.out.println("Invalid pubkey");
            }
        }
        catch (NoSuchAlgorithmException e) {
            System.out.println("RSA algorithm not available");
            System.out.println("Failed to setup RSA keys");
        }
        catch (IOException io) {
            System.out.println("Failed to validate RSA keys");
        }
    }

    /**
     * Helper method to generate a RSA cipher
     * @return the RSA cipher
     */
    private Cipher getCipher() {
        try {
            return Cipher.getInstance("RSA");
        }
        catch (NoSuchAlgorithmException e) {
            System.out.println("RSA algorithm not available");
        }
        catch (NoSuchPaddingException pad) {
            System.out.println("Padding Exception: " + pad.getMessage());
        }
        return null;
    }

    /**
     * Helper method to encrypt a given text
     * @param plainText the string to be encrypted
     * @return the encrypted value
     */
    private String encrypt(String plainText){
        assert this.remoteAddress != null && !this.remoteAddress.isEmpty();
        try {
            Cipher encryptCipher = this.getCipher();
            assert encryptCipher != null;
            encryptCipher.init(Cipher.ENCRYPT_MODE, this.remotePubKey);

            byte[] plainTextBytes = plainText.getBytes();
            byte[] encryptedBytes = encryptCipher.doFinal(plainTextBytes);

            return Base64.getEncoder().encodeToString(encryptedBytes);
        }
        catch (InvalidKeyException key) {
            System.out.println("Invalid key exception: " + key.getMessage());
        }
        catch (IllegalBlockSizeException block) {
            System.out.println("Invlaid Blocksize for encryption: " + block.getMessage());
        }
        catch (BadPaddingException badpad){
            System.out.println("Bad padding exception: " + badpad.getMessage());
        }
        return null;
    }

    /**
     * helper method to decrypt the message received from the server
     * @param encryptedText the encrypted text from the other proxy
     * @return the decrypted clear text
     */
    private String decrypt(String encryptedText){
        try {
            Cipher decryptCipher = this.getCipher();
            assert decryptCipher != null;
            decryptCipher.init(Cipher.DECRYPT_MODE, this.getPrivateKey());

            byte[] encryptedTextBytes = Base64.getDecoder().decode(encryptedText);
            byte[] decryptedBytes = decryptCipher.doFinal(encryptedTextBytes);

            return new String(decryptedBytes);
        }
        catch (InvalidKeyException key) {
            System.out.println("Invalid key exception: " + key.getMessage());
        }
        catch (IllegalBlockSizeException block) {
            System.out.println("Invlaid Blocksize for encryption: " + block.getMessage());
        }
        catch (BadPaddingException badpad){
            System.out.println("Bad padding exception: " + badpad.getMessage());
        }
        return null;
    }

    // Getters and Setters

    private PrivateKey getPrivateKey(){
        return this.keyPair.getPrivate();
    }

    private PublicKey getPublicKey(){
        return this.keyPair.getPublic();
    }
}
