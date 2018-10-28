package tunnelrsa;


import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.util.logging.Level;
import java.util.logging.Logger;
import tunnelrsa.Rsa;



/**
 * Class representing the "remote" server on given host and given port: it redirects communication to remote_host and remote_port.
 * The "remote" server waits for a client and when one connects, sends him his public RSA key, then wait for the symmetric key of the latter.
 * @author Johan Jobin, University Of Fribourg, 2018
 */
public class Remote {
    
    private int port;
    private String host;
    private String host_remote;
    private int port_remote;
    private ServerSocket server = null;
    private boolean isRunning = true;   
    private Rsa RsaKeys;
    private byte[] symmetricKeyAttribute =null;

    public Remote(String host, int port, String host_remote, int port_remote){
        Rsa myRSAKeys = new Rsa(2048);
        this.RsaKeys = myRSAKeys;
        this.host = host;
        this.port=port;
        this.host_remote = host_remote;
        this.port_remote = port_remote;
        try {
            server = new ServerSocket(this.port, 100, InetAddress.getByName(this.host));
        }catch (IOException ex) {
            Logger.getLogger(Remote.class.getName()).log(Level.SEVERE, null, ex);
        }   
    }
   
   
    public void startServer(){
        Thread t = new Thread(new Runnable(){
            public void run(){
                while(isRunning == true){
                    Socket client;
                    try {
                        //Wait for a client
                        System.out.println("Listening...");
                        client = server.accept();
                        InputStream streamFromLocal = client.getInputStream();
                        OutputStream streamToLocal = client.getOutputStream();
                        
                        if(symmetricKeyAttribute==null){
                            //Send public key
                            System.out.println("Sending public key...");
                            Integer size = RsaKeys.getPublicKey().toByteArray().length+4;
                            ByteBuffer bb = ByteBuffer.allocate(4); 
                            bb.putInt(size.intValue());
                            byte[] sizeBytesArray = bb.array();
                            byte[] publicKeyByteArray= RsaKeys.getPublicKey().toByteArray();
                            byte[] toSend= new byte[size];
                            System.arraycopy(sizeBytesArray, 0, toSend, 0, 4);
                            System.arraycopy(publicKeyByteArray, 0, toSend, 4,publicKeyByteArray.length);
                            streamToLocal.write(toSend);
                            streamToLocal.flush();
                            
                            //Send n
                            System.out.println("Sending n...");
                            Integer sizeN = RsaKeys.getN().toByteArray().length+4;
                            ByteBuffer bbN = ByteBuffer.allocate(4);
                            bbN.putInt(sizeN.intValue());
                            byte[] sizeBytesArrayN = bbN.array();
                            byte[] byteArrayN = RsaKeys.getN().toByteArray();
                            byte[] toSendN = new byte[sizeN];;
                            System.arraycopy(sizeBytesArrayN, 0, toSendN, 0, 4);
                            System.arraycopy(byteArrayN, 0, toSendN, 4, byteArrayN.length);
                            streamToLocal.write(toSendN);
                            streamToLocal.flush();
                           
                            //Receive encrypted symmetric and decrypt it
                            System.out.println("Decrypting symmetric key");
                            byte[] header = new byte[4];
                            int headerSize= streamFromLocal.read(header);
                            int numberOfBytesOfPacket= ByteBuffer.wrap(header).getInt();
                            byte[] symmetricKey = new byte[numberOfBytesOfPacket-4];
                            int bytesRead2 = streamFromLocal.read(symmetricKey);
                            try {
                                symmetricKeyAttribute = RsaKeys.decrypt(new BigInteger(symmetricKey)).toByteArray();
                            }catch (Exception ex) {
                                Logger.getLogger(Remote.class.getName()).log(Level.SEVERE, null, ex);
                            }
                        }
                        
                        Socket socketToNext = new Socket(host_remote, port_remote);
                        InputStream streamFromRecipient = socketToNext.getInputStream();
                        OutputStream streamToRecipient = socketToNext.getOutputStream();
                       
 
                        System.out.println("Starting secured communication");
                        Thread t1 = new Thread(new ClientHandler(streamFromLocal, streamToRecipient, 1,symmetricKeyAttribute));
                        Thread t2 = new Thread(new ClientHandler(streamFromRecipient,streamToLocal, 0,symmetricKeyAttribute ));
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
   
   
   public void stopServer(){
       isRunning = false;
   }
}
