/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package tunnelrsa;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Handle the communication for the "local/remote" server. It has two modes:
 * 0) clear InputStream --> encrypt --> encrypted OutputStream
 * 1) clear OutputStream -- decrypt -- encrypted InputStream
 * @author Johan Jobin UNIFR
 */
public class ClientHandler implements Runnable{
    
    private InputStream streamFrom;
    private OutputStream streamTo;
    private byte[] sharedKey=null;
    private int mode; //0: CLEAR --> ENCRYPT WITH HEADER  1: ENCRYPTED WITH HEADER --> CLEAR
    private AesGcmEncryption aes;
    

    public ClientHandler(InputStream streamFrom, OutputStream streamTo, int mode, byte [] symmetricKey){
       this.streamFrom = streamFrom; 
       this.streamTo = streamTo;
       this.sharedKey=symmetricKey;
       this.mode=mode;
       this.aes= new AesGcmEncryption();
    }

    @Override
    public void run(){
        //encrypt
        if(mode==0){
            byte[] b = new byte[2048]; 
            try {
                while(true){
                    int bytesRead = streamFrom.read(b);
                    if(bytesRead==-1) {
                        break;
                    }
                    
                    //Header
                    byte[] encrypted = aes.encrypt(sharedKey, b, "test".getBytes());
                    if(encrypted.length < 0) {break; }
                    byte[] len = new byte[4];
                    ByteBuffer.wrap(len).putInt(encrypted.length);
                    int size= encrypted.length+4;
                    byte[] toSend= new byte[size];
                    
                    //Send encrypted data
                    System.arraycopy(len, 0, toSend, 0, 4);
                    System.arraycopy(encrypted, 0, toSend, 4, encrypted.length);
                    System.out.println("Sending data of length: " +toSend.length);
                    streamTo.write(toSend);
                    streamTo.flush();
                }
            }catch(Exception e){
                Logger.getLogger(this.getClass().getName()).log(Level.SEVERE, e.getMessage());
            } 
        }
        //Decrypt
        else{
            try{                            
                while(true){
                    //read header
                    byte[] headerN = new byte[4];
                    int headerNSize= streamFrom.read(headerN);
                    if(headerNSize==-1){break;}
                    int numberOfBytesOfPacket= ByteBuffer.wrap(headerN).getInt();
                    
                    //read content
                    byte[] a = new byte[numberOfBytesOfPacket];
                    int bytesRead2 = streamFrom.read(a);
                    if(bytesRead2==-1){
                        break;
                    }
                    byte[] decrypted = aes.decrypt(sharedKey, a, "test".getBytes());
                    System.out.println("Decrypted "+ new String(decrypted));
                    streamTo.write(decrypted);
                    streamTo.flush();  
                }
            }catch(Exception e){
                Logger.getLogger(this.getClass().getName()).log(Level.SEVERE, e.getMessage());
            }
        }      
    }      
        
}
    
    

