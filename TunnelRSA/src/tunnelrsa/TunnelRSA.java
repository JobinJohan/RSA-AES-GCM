package tunnelrsa;
import static java.lang.Integer.parseInt;


/**
 * Multithread Server implementing RSA tunnel using AES-GCM as an authenticated encryption cipher suite.
 * @author Johan Jobin, University Of Fribourg, 2018
 * 
 * 
 */
public class TunnelRSA {
    
   private static final int LOCAL_MODE = 0;
   private static final int REMOTE_MODE=1;
    
    /**
     * @param args the command line arguments: java tunnelrsa/TunnelRSA mode local_host local_port remote_host remote_port
     */
    public static void main(String[] args) {
        if(args.length!=5){
            System.out.println("Too few arguments, example: java tunnelrsa/TunnelRSA <mode> <local host> <local port> <remote host> <remote port>");
            System.exit(0);
        }

        else if(parseInt(args[0])==LOCAL_MODE){
            String host = new String(args[1]);
            String host_remote = new String(args[3]);
            int port = Integer.parseInt(args[2]);
            int port_remote = Integer.parseInt(args[4]);
            Local localServer = new Local(host, port, host_remote, port_remote);
            localServer.startServer();
        }
        
        else if(parseInt(args[0])== REMOTE_MODE){
            String host = new String(args[1]);
            String host_remote = new String(args[3]);
            int port = Integer.parseInt(args[2]);
            int port_remote = Integer.parseInt(args[4]);
            Remote remoteServer = new Remote(host, port, host_remote, port_remote);
            remoteServer.startServer();
        }
        
        else{
            System.out.println("Arguments not valid, please try again, example: java tunnelrsa/TunnelRSA <mode> <local host> <local port> <remote host> <remote port> ");
        }
    }
    
}
