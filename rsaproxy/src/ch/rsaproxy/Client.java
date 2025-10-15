/**
 * Basic rsaproxy.Client Implementation for the RSA Proxy
 * @author: Michael Kaiser
 */
package ch.rsaproxy;

import java.io.*;
import java.net.*;


public class Client {

    // instance variables
    private String proxyAddress;
    private int proxyPort;
    private Socket socket;
    private DataInputStream in;
    private DataOutputStream out;


    /**
     * Constructor of rsaproxy.Client
     * @param address the address of the server for the client
     * @param port the port of the server for the client;
     */
    public Client(String address, int port) {
        assert port > 0 && port < 65535;
        assert address != null && !address.isEmpty();

        this.proxyAddress = address;
        this.proxyPort = port;

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
        System.out.println("Connecting to server " + proxyAddress + ":" + proxyPort);
        try {
            this.socket = new Socket(this.proxyAddress, this.proxyPort);
            this.in = new DataInputStream(System.in);
            this.out = new DataOutputStream(this.socket.getOutputStream());
            System.out.println("Connected to server " + proxyAddress + ":" + proxyPort);
        }
        catch (IOException e) {
            System.out.println("Could not connect to " + this.proxyAddress + ":" + this.proxyPort + e);
        }
        this.invariant();
    }

    /**
     * close all the sockets that may be open
     */
    private void closeAll() {

        try {
            this.in.close();
            this.out.close();
            this.socket.close();
        }
        catch (IOException i){
            System.out.println("Could not close socket " + this.proxyAddress + ":" + this.proxyPort + i);
        }
    }

    /**
     * Method to run the client
     */
    public void run() {
        System.out.println("Starting client...");
        this.init();

        String msg = "";
        while (!msg.equals("kill")) {
            try {
                msg = this.in.readLine();
                this.out.writeUTF(msg);
            }
            catch (IOException e) {
                System.out.println("Could not read from " + this.proxyAddress + ":" + this.proxyPort + e);
            }
        }

        // the while loop has terminated
        // can now close everything
        this.closeAll();
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