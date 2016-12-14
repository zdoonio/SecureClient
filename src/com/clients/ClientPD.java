package com.clients;

import com.security.IvGenerator;
import com.security.KeyAgreementEntity;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.spec.IvParameterSpec;

/**
 *
 * @author Karol
 */
public class ClientPD implements DecEncClient {

    public final String name;
    
    public final static int ALICE = 0;
    
    public final static int BOB = 1;
    
    private final KeyAgreementEntity kae;
    
    public ClientPD(String name) {
        this.name = name;
        kae = new KeyAgreementEntity();
    }
    
    public void init(int BobOrAlice, String password) throws 
            NoSuchAlgorithmException, InvalidKeySpecException, Exception {
        switch (BobOrAlice) {
            case ALICE:
                kae.generatePredistributedKey(password);
                kae.generateSessionKey();
                
                break;
            case BOB:
                kae.generatePredistributedKey(password);
                break;
            default:
                throw new Exception();
        }
    }
    
    public void receiveSessionKey(ByteArrayOutputStream boas) {
        byte[] key = boas.toByteArray();
        kae.decryptSessionKey(key);
        
    }
    
    public ByteArrayOutputStream encryptSessionKey() throws IOException {
        ByteArrayOutputStream boas = new ByteArrayOutputStream();
        byte[] key = kae.encryptSessionKey();
        boas.write(key, 0, key.length);
        boas.close();
        return boas;
    }

    @Override
    public byte[] encrypt(String message, IvParameterSpec iv) {
        return kae.encrypt(message, iv);
    }

    @Override
    public String decrypt(byte[] message, IvParameterSpec iv) {
        return kae.decrypt(message, iv);
    }

    @Override
    public ByteArrayOutputStream writeMessage(byte[] encryptedMessage) {
        return null;
    }

    @Override
    public byte[] receiveMessage(ByteArrayOutputStream encryptedMessage) {
        return null;
    }
    
    
    public static void main(String[] args) throws InvalidKeySpecException, Exception {
        
        String password = "gowno";
        
        ClientPD Alice = new ClientPD("Alice");
        Alice.init(ClientPD.ALICE, password);
        
        ClientPD Bob = new ClientPD("Bob");
        Bob.init(ClientPD.BOB, password);
        
        ByteArrayOutputStream key = Alice.encryptSessionKey();
        
        Bob.receiveSessionKey(key);
        
        IvParameterSpec iv = IvGenerator.generateIV(IvGenerator.AES_BLOCK_SIZE);
        
        byte[] encryption = Alice.encrypt("Zamknij mordę", iv);
        
        String decryption = Bob.decrypt(encryption, iv);
        
        System.out.println(decryption);
        
    }
    
}
