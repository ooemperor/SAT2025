/**
 * Basic rsaproxy.Client Implementation for the RSA Proxy
 *
 * @author: Michael Kaiser
 */
package ch.rsaproxy;

import java.io.*;
import java.net.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;


public class Client {

    // instance variables
    private String proxyAddress;
    private int proxyPort;
    private Socket socket;
    private InputStreamReader input;
    private BufferedReader in;
    private DataOutputStream out;
    private DataInputStream fromServer;
    private volatile boolean shutdown = false;
    private final ExecutorService threadpool;


    /**
     * Constructor of rsaproxy.Client
     *
     * @param address the address of the server for the client
     * @param port    the port of the server for the client;
     */
    public Client(String address, int port) {
        assert port > 0 && port < 65535;
        assert address != null && !address.isEmpty();

        this.proxyAddress = address;
        this.proxyPort = port;

        this.threadpool = Executors.newCachedThreadPool();

        this.invariant();
    }

    /**
     * invariant method to check for consistency
     */
    private void invariant() {
        assert proxyAddress != null;
        assert proxyPort > 0 && proxyPort < 65535;
    }

    /**
     * initialize the variables
     */
    private void init() {
        this.invariant();
        this.log("Connecting to server " + proxyAddress + ":" + proxyPort);
        try {
            this.socket = new Socket(this.proxyAddress, this.proxyPort);
            this.input = new InputStreamReader(System.in);
            this.in = new BufferedReader(this.input);
            this.out = new DataOutputStream(this.socket.getOutputStream());
            this.fromServer = new DataInputStream(this.socket.getInputStream());
            this.log("Connected to server " + proxyAddress + ":" + proxyPort);
        } catch (IOException e) {
            this.log("Could not connect to " + this.proxyAddress + ":" + this.proxyPort + e);
        }
        this.invariant();
    }

    /**
     * close all the sockets that may be open
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
        this.log("Starting client...");
        this.init();
        Future<?> sendToServer = this.threadpool.submit(this::sendToServer);
        Future<?> readFromServer = this.threadpool.submit(this::readFromServer);
        while (!this.shutdown) {
        }
    }

    /**
     * Send my local traffic to the server
     */
    private void sendToServer() {
        String msg = "";
        while (!msg.equals("kill") && !this.shutdown) {
            try {
                msg = this.in.readLine();
                this.out.writeUTF(msg);
            } catch (IOException e) {
                this.log("Could not send to " + this.proxyAddress + ":" + this.proxyPort + e);
            }
        }

        // the while loop has terminated
        // can now close everything
        this.shutdown();
    }

    /**
     * Read the traffic coming from the remote server
     */
    private void readFromServer() {
        String msg = "";
        while (!msg.equals("kill") && !this.shutdown) {
            try {
                msg = this.fromServer.readUTF();
                this.log("Remote: " + msg);
            } catch (IOException e) {
                this.log("Could not read from " + this.proxyAddress + ":" + this.proxyPort + e);
            }
        }

        // the while loop has terminated
        // can now close everything
        this.shutdown();
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

    //Getters and setters here

    public int getProxyPort() {
        return this.proxyPort;
    }

    public void setProxyPort(int proxyPort) {
        this.proxyPort = proxyPort;
    }

    public String getProxyAddress() {
        return this.proxyAddress;
    }

    public void setProxyAddress(String proxyAddress) {
        this.proxyAddress = proxyAddress;
    }
}