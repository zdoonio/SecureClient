
package com.clients;

import com.security.DiffieHellman;
import com.security.IvGenerator;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.IvParameterSpec;

/**
 *
 * @author Karol
 */
public class ClientDH implements DecEncClient {
    
    /**
     * The name of this Client.
     */
    public final String name;
    
    private final DiffieHellman dh;
    
    public ClientDH(String name) {
        this.name = name;
        dh = new DiffieHellman();
        dh.generateKeys();
    }
    
    public void receivePublicKey(byte[] bytes) throws IOException, ClassNotFoundException {
        ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
        BufferedInputStream bis = new BufferedInputStream(bais);
        try (ObjectInputStream ois = new ObjectInputStream(bis)) {
            Object obj = ois.readObject();
            if( !(obj instanceof DHPublicKey) ) throw new ClassNotFoundException();
            else {
                dh.receivePublicKey((DHPublicKey) obj); 
                dh.generateSharedSecret();
            }
            ois.close();
        } 
        
    }
    
    public byte[] writePublicKey() throws IOException {
        byte[] myBytes;
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            BufferedOutputStream bois = new BufferedOutputStream(bos);
            ObjectOutputStream oos = new ObjectOutputStream(bois);
            oos.writeObject(dh.getPublicKey());
            oos.flush();
            myBytes = bos.toByteArray();
        }
        return myBytes;
    }
    
    /**
     *
     * @param message
     * @param iv
     * @return
     */
    @Override
    public byte[] encrypt(String message, IvParameterSpec iv) {
        return dh.encrypt(message, iv);
    }
    
    /**
     *
     * @param ciphertext
     * @param iv
     * @return
     */
    @Override
    public String decrypt(byte[] ciphertext, IvParameterSpec iv) {
        return dh.decrypt(ciphertext, iv);
    }
    
    @Override
    public ByteArrayOutputStream writeMessage(byte[] encryptedMessage) {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            baos.write(encryptedMessage, 0, encryptedMessage.length);
            baos.close();
            return baos;
        } catch (IOException ex) {
            Logger.getLogger(ClientDH.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    @Override
    public byte[] receiveMessage(ByteArrayOutputStream encryptedMessage) {
        return encryptedMessage.toByteArray();
    }
    
    
    public static void main(String[] args) {
        try {
            ClientDH karol = new ClientDH("Karol");
            
            byte[] karolkey = karol.writePublicKey();
            
            ClientDH dominik = new ClientDH("Dominik");
            
            dominik.receivePublicKey(karolkey);
            
            byte[] dominikkey = dominik.writePublicKey();
            
            karol.receivePublicKey(dominikkey);
            
            String message = "gogwfffknkf wfwefkmwfkmeg";
            
            IvParameterSpec iv = IvGenerator.generateIV(IvGenerator.AES_BLOCK_SIZE);
            
            byte[] encryption = karol.encrypt(message, iv);
            
            ByteArrayOutputStream baos = karol.writeMessage(encryption);
            
            byte[] received = dominik.receiveMessage(baos);
            
            String decryption = dominik.decrypt(received, iv);
            
            System.out.println(decryption);
            
            
        } catch (IOException | ClassNotFoundException ex) {
            Logger.getLogger(ClientDH.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        
        
    }
    
}
