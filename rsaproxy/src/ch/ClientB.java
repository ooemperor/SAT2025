/**
 * File for the implementation of client B of the RSA Proxy
 * @author: Michael Kaiser
 */
package ch;
import ch.rsaproxy.Client;

public class ClientB{
    public ClientB(){};

    public static void main(String[] args){
        Client client = new Client("127.0.0.1", 9000);
        client.run();
    }
};

