/**
 * File for the implementation of Server A of the RSA Proxy
 * @author: Michael Kaiser
 */
package ch;
import ch.rsaproxy.Server;

public class ServerB {
    public ServerB(){}

    public static void main(String[] args){
        Server serverB = new Server("127.0.0.1", 8001, 9000, 9001);
        serverB.run();
    }
}