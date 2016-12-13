
package com.security;

import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author Karol
 * TODO : serializable public key
 */
public class DiffieHellman implements CBCEncryptable {
    
    private DHPublicKey publicKey;
    private DHPrivateKey privateKey;
    
    private DHPublicKey receivedPublicKey;
    
    private byte[] secretKey;
    
    private SecureRandom random;
    
    /**
     * Algorithm used for shortening the key in order to encrypt and decrypt messages.
     */
    public static final String KEY_ALGORITHM = EnabledCiphers.AES;
    
    /**
     * Algorithm used for encrypting and decrypting of messages.
     */
    public static final String CIPHER_ALGORITHM = EnabledCiphers.AES_CBC;
    
    public void generateKeys() {
        try {
            final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH");
            random = SecureRandom.getInstance("SHA1PRNG"); //buiduje Sie
            keyPairGenerator.initialize(1024, random);
            final KeyPair keyPair = keyPairGenerator.generateKeyPair();
            publicKey = (DHPublicKey) keyPair.getPublic();
            privateKey = (DHPrivateKey) keyPair.getPrivate();
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(DiffieHellman.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    
    /**
     * TODO: Receive a serialized key.
     * @param publicKey 
     */
    public void receivePublicKey(String name) {
        receivedPublicKey = publicKey;
        String location = "keysdh/pubkeydh"+name+".key";
    }
    
    /**
     * Generate a secret key used for encryption between two parties.
     */
    public void generateSharedSecret() {
        try {
            final KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
            keyAgreement.init(privateKey);
            keyAgreement.doPhase(receivedPublicKey, true);
            secretKey = keyAgreement.generateSecret();
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(DiffieHellman.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(DiffieHellman.class.getName()).log(Level.SEVERE, null, ex);
        }
        
    }
    
    
    public byte[] encrypt(final String message, final IvParameterSpec iv) {
        
        try {
            final Key key = shortenKey(secretKey);
            final Cipher cipher  = Cipher.getInstance(CIPHER_ALGORITHM);
                       
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
            
            final byte[] encryptedMessage = cipher.doFinal(message.getBytes());
            return encryptedMessage;
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(DiffieHellman.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(DiffieHellman.class.getName()).log(Level.SEVERE, null, ex);
        }  catch (IllegalBlockSizeException ex) {
            Logger.getLogger(DiffieHellman.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(DiffieHellman.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(DiffieHellman.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidAlgorithmParameterException ex) { 
            Logger.getLogger(DiffieHellman.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeySpecException ex) {
            Logger.getLogger(DiffieHellman.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
        
    }
    
    
    public String decrypt(byte[] ciphertext, IvParameterSpec iv) {
        try {
            final Key key = shortenKey(secretKey);
            final Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);

            cipher.init(Cipher.DECRYPT_MODE, key, iv, random);
          
            String secretMessage = new String(cipher.doFinal(ciphertext));
            return secretMessage;
        } catch (InvalidKeyException ex) {
            Logger.getLogger(DiffieHellman.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidAlgorithmParameterException ex) {
            Logger.getLogger(DiffieHellman.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(DiffieHellman.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeySpecException ex) {
            Logger.getLogger(DiffieHellman.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(DiffieHellman.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(DiffieHellman.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(DiffieHellman.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
    
    public Key shortenKey(final byte[] longKey) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException { 
     
            int AES_KEY_LEN = 128 / 8;
            final byte[] key = new byte[AES_KEY_LEN];
            System.arraycopy(longKey, 0, key, 0, AES_KEY_LEN);
            final Key keySpec = new SecretKeySpec(key, KEY_ALGORITHM);
            return keySpec;   
 
    } 
    
    public void keySave(String name) throws FileNotFoundException{
    	
    	//int blocksize = IvGenerator.AES_BLOCK_SIZE;
    	//DiffieHellman df = new DiffieHellman();
    	//df.generateKeys();
    	PrintWriter pubKey = new PrintWriter("keysdh/pubkeydh"+name+".key");
        pubKey.println(publicKey);
        pubKey.close();
    }

    
    /**
     * How use this class when agreeing on a key
     * @param args 
     * @throws FileNotFoundException 
     */
    public static void main(String[] args) throws FileNotFoundException {

        int blocksize = IvGenerator.AES_BLOCK_SIZE;
        DiffieHellman df = new DiffieHellman();
        df.generateKeys();

        DiffieHellman df2 = new DiffieHellman();
        df2.generateKeys();
        //df.receivePublicKey(df2.getPublicKey());

        //df2.receivePublicKey(df.getPublicKey());
        
        //System.out.println(df.getPublicKey());
        //System.out.println(df2.getPublicKey());
        String name = "Alice";
        PrintWriter pubKey = new PrintWriter("keysdh/pubkeydh"+name+".key");
        //pubKey.println(df.getPublicKey());
        pubKey.close();
        df2.keySave("Leszek");
        df.generateSharedSecret();
        df2.generateSharedSecret();

        // jeśli mode to CBC, trzeba podać IV
        IvParameterSpec iv = IvGenerator.generateIV(blocksize);

        byte[] encryption = df.encrypt("111111112222222211111111"
                + "222222221111111122222222", iv);
        System.out.println(Arrays.toString(encryption));

        String decryption = df2.decrypt(encryption, iv);
        System.out.println(decryption);
    
        
    }
    
    
    
}
