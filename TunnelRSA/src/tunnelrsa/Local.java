package tunnelrsa;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Class representing the "local" server on given host and given port
 * The "local" server waits for the public RSA key of the "remote" server and replies by sending his encrypted symmetric key
 * @author Johan Jobin, University Of Fribourg, 2018
 * 
 */
public class Local {
    
   private int port;
   private String host;
   private String host_remote;
   private int port_remote;
   private ServerSocket server = null;
   private boolean isRunning = true;   
   private Rsa myRsaKeys=null;
   private byte[] sharedKey;
  
   public Local(String host, int port, String host_remote, int port_remote){
       this.host = host;
       this.port=port;
       this.host_remote = host_remote;
       this.port_remote = port_remote;
       
       // Generate a random symmetric key and avoid it to be negative
       SecureRandom secRandom = new SecureRandom() ;
       byte[] key = new byte[16];
       ByteBuffer realKey = ByteBuffer.wrap(new byte[16]);
       secRandom.nextBytes(key);
       ByteBuffer keyWrapped = ByteBuffer.wrap(key);
       realKey.putInt(Math.abs(keyWrapped.getInt(0)));
       realKey.putInt(Math.abs(keyWrapped.getInt(4)));
       realKey.putInt(Math.abs(keyWrapped.getInt(8)));
       realKey.putInt(Math.abs(keyWrapped.getInt(12)));
       this.sharedKey= realKey.array();
       
       //Socket for incoming clients
       try{
           server = new ServerSocket(this.port, 100, InetAddress.getByName(this.host));
       }catch (IOException ex){
           Logger.getLogger(Remote.class.getName()).log(Level.SEVERE, null, ex);
       }  
   }
   
/**
 * Start the server as the "local" server on given host, port and redirect communication to remote_host and remote_port 
 * @author Johan Jobin, University Of Fribourg, 2018
 * 
 */
   public void startServer(){
        Thread t = new Thread(new Runnable(){
            public void run(){
                System.out.println("Listening...");
                while(isRunning == true){
                    //Waiting for a client
                    Socket client;
                    try {
                        client = server.accept(); 
                        InputStream streamFromLocal = client.getInputStream();
                        OutputStream streamToLocal = client.getOutputStream();
       
                        Socket socketToNext = new Socket(host_remote, port_remote);
                        InputStream streamFromRecipient = socketToNext.getInputStream();
                        OutputStream streamToRecipient = socketToNext.getOutputStream();
                        
                        //Before transmission of data (Key exchange)
                        if(myRsaKeys==null){
                            
                            //Receive public key
                            System.out.println("Receiving public key from remote host...");
                            byte[] header = new byte[4]; 
                            int headerSize = streamFromRecipient.read(header);
                            int numberOfBytesOfPacket = ByteBuffer.wrap(header).getInt();
                            byte[] publicKey = new byte[numberOfBytesOfPacket-4];
                            int bytesread= streamFromRecipient.read(publicKey);

                            //Receive n to complete the public key
                            byte[] headerN = new byte[4];
                            int headerNSize= streamFromRecipient.read(headerN);
                            int numberOfBytesOfPacketN= ByteBuffer.wrap(headerN).getInt();
                            byte[] n = new byte[numberOfBytesOfPacketN-4];
                            int bytesRead2 = streamFromRecipient.read(n);

                            //Create a Rsa object in order to encryp/decrypt
                            myRsaKeys = new Rsa(new BigInteger(publicKey),new BigInteger(n));
                            
                            //Encrypt the symmetric key and send it to the remote node
                            System.out.println("Sending encrypted symmetric key...");
                            BigInteger encryptedSharedKey= myRsaKeys.encrypt(new BigInteger(sharedKey));
                            Integer size = encryptedSharedKey.toByteArray().length+4;
                            ByteBuffer bb = ByteBuffer.allocate(4);
                            bb.putInt(size.intValue());
                            byte[] sizeBytesArray = bb.array();
                            byte[] byteArray = encryptedSharedKey.toByteArray();
                            byte[] toSend = new byte[size];
                            System.arraycopy(sizeBytesArray, 0, toSend, 0, 4);
                            System.arraycopy(byteArray, 0, toSend, 4, byteArray.length);
                            streamToRecipient.write(toSend);
                            streamToRecipient.flush();
                        }
                        
                        System.out.println("Client connected, secured communication starting...");
                        Thread t1 = new Thread(new ClientHandler(streamFromLocal, streamToRecipient, 0, sharedKey));
                        Thread t2 = new Thread(new ClientHandler(streamFromRecipient,streamToLocal, 1, sharedKey ));
                        t1.start();
                        t2.start();
                    }catch (IOException ex) {
                        Logger.getLogger(Remote.class.getName()).log(Level.SEVERE, null, ex);
                    }  
                }
            }
        });
        t.start();
    }
   
   /**
 * Stop the server 
 * @author Johan Jobin, University Of Fribourg, 2018
 * 
 */
    public void stopServer(){
       isRunning = false;
    }
}
