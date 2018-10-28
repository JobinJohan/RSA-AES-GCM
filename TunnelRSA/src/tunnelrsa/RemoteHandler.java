
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package tunnelrsa;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Johan Jobin UNIFR
 */
public class RemoteHandler implements Runnable{
    
    private InputStream streamFromLocal;
    private OutputStream streamToRecipient;

    public RemoteHandler(InputStream streamFromLocal, OutputStream streamToRecipient){
       this.streamFromLocal = streamFromLocal; 
       this.streamToRecipient = streamToRecipient;
    }

    @Override
    public void run(){
        byte[] b = new byte[2048]; 
        try {
            while(true){
                int bytesRead = streamFromLocal.read(b);
                if(bytesRead==-1)break;
                streamToRecipient.write(b, 0, bytesRead);
                streamToRecipient.flush();                           
            }
        }catch(IOException ex){
            Logger.getLogger(RemoteHandler.class.getName()).log(Level.SEVERE, null, ex);
        }
        
    }      
        
}
    
    

