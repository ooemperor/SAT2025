/**
 * File for the implementation of client A of the RSA Proxy
 * @author: Michael Kaiser
 */
package ch;
import ch.rsaproxy.Client;

public class ClientA{
    public ClientA(){};

    public static void main(String[] args){
        Client client = new Client("127.0.0.1", 8000);
        client.run();
    }
};

