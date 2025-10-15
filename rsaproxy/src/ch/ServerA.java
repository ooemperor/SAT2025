/**
 * File for the implementation of Server A of the RSA Proxy
 * @author: Michael Kaiser
 */
package ch;
import ch.rsaproxy.Server;

public class ServerA {
    public ServerA(){}

    public static void main(String[] args){
        Server serverA = new Server("127.0.0.1", 9001, 8000, 8001);
        serverA.run();
    }
}
