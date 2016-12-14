
package com.security;


import com.utils.HexUtils;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * For now this class is intended to use
 * when agreeing on a key between two parties,
 * with distribution of keys from 
 * predistributed keys. 
 * 
 * This class represents an entity like Alice and Bob, 
 * which would be communicating.
 * 
 * 
 * @author Karol
 * 
 */
public class KeyAgreementEntity implements CBCEncryptable {


    /**
     * Algorithm used for encryption and decryption of messages.
     */
    public final String CIPHER_ALGO = EnabledCiphers.AES_CBC;
    
    
    /**
     * Algorithm for encryption of a session key. 
     * Because session key will be for AES128 encryption then 
     * the provided mode can be ECB used for encryption of this key.
     */
    public final String KEY_ALGO = EnabledCiphers.AES;
    
    /**
     * Size of predistributed key.
     */
    public final int KEY_SIZE = 128 / 8;
    
    
    /**
     * used for encrypting the session key
     */
    private SecretKeySpec predistributedKey;
    

    private SecretKey generatedSessionKey;
    
    private SecretKey decryptedSessionKey;
    
    /**
    * session key used for real encrypting 
    * and decrypting of messages.
    */
    private SecretKey sessionKey;
    
    private final int sessionKeyLen = EnabledCiphers.AES_KEY_LEN_BYTES;
    
    
    private final static byte[] salt = new byte[16];
    
    
    public KeyAgreementEntity() {
        super();
    }

    public void generateSessionKey() {
        SecretKeySpec sk = generateKey(sessionKeyLen, KEY_ALGO);
        this.generatedSessionKey = sk;
        agreeOnGeneratedSessionKey();
    }
    
    public void generatePredistributedKey(String password) throws 
            NoSuchAlgorithmException, InvalidKeySpecException {
        String hash = PBKDF.createKey(password, KEY_SIZE, salt);
                
        byte[] key = HexUtils.fromHex(hash);
        this.predistributedKey = new SecretKeySpec(key, KEY_ALGO);
        
    }
    
    private SecretKeySpec generateKey(int keyLen, String algorithm) {
        SecureRandom random = new SecureRandom();
        byte[] key = new byte[keyLen];
        random.nextBytes(key);
        SecretKeySpec sk = new SecretKeySpec(key, algorithm);
        return sk;
    }
    
    public byte[] encryptSessionKey() {
        try {
            Cipher cipher = Cipher.getInstance(KEY_ALGO);
            cipher.init(Cipher.ENCRYPT_MODE, predistributedKey);
            byte[] sessionKeyByte = generatedSessionKey.getEncoded();
            byte[] encrypted = cipher.doFinal(sessionKeyByte);
            return encrypted;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(KeyAgreementEntity.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
    
    public void decryptSessionKey(byte[] encSessionKey) {
        try {
            Cipher cipher = Cipher.getInstance(KEY_ALGO);
            cipher.init(Cipher.DECRYPT_MODE, predistributedKey);
            byte[] decrypted = cipher.doFinal(encSessionKey);
            decryptedSessionKey = new SecretKeySpec(decrypted, KEY_ALGO);
            agreeOnDecryptedSessionKey();
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException ex) {
            Logger.getLogger(KeyAgreementEntity.class.getName()).log(Level.SEVERE, null, ex);
        } 
    }
    
    private void agreeOnDecryptedSessionKey() {
        this.sessionKey = decryptedSessionKey;
    }

    private void agreeOnGeneratedSessionKey() {
        this.sessionKey = generatedSessionKey;
    }
    
    /**
     * encrypt method overriding CBCEncryptable interface.
     * @param plaintext
     * @param iv
     * @return 
     */
    @Override
    public byte[] encrypt(String plaintext, IvParameterSpec iv) {
        try {
            Cipher cipher = Cipher.getInstance(CIPHER_ALGO);
            cipher.init(Cipher.ENCRYPT_MODE, sessionKey, iv);
            byte[] encryption = cipher.doFinal(plaintext.getBytes());
            return encryption;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(KeyAgreementEntity.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    /**
     * decrypt method overriding CBCEncryptable interface.
     * @param ciphertext
     * @param iv
     * @return 
     */
    @Override
    public String decrypt(byte[] ciphertext, IvParameterSpec iv) {
        try {
            Cipher cipher = Cipher.getInstance(CIPHER_ALGO);
            cipher.init(Cipher.DECRYPT_MODE, sessionKey, iv);
            byte[] decipheredbytes = cipher.doFinal(ciphertext);
            return new String(decipheredbytes);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(KeyAgreementEntity.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
        
    }
    
    
    public static void main(String args[]) throws NoSuchAlgorithmException, InvalidKeySpecException {
        
        // iv do enkrypcji
        IvParameterSpec iv = IvGenerator.generateIV(IvGenerator.AES_BLOCK_SIZE);
        
        // alice nawiązuje połączenie z Bobem.
        KeyAgreementEntity Alice = new KeyAgreementEntity();
        KeyAgreementEntity Bob = new KeyAgreementEntity();

        // Alicja generuje klucz
        String password = "gowno";
        Alice.generatePredistributedKey(password);
        Bob.generatePredistributedKey(password);
        
        Bob.generateSessionKey();
        byte[] encryptedSessionKey = Bob.encryptSessionKey();
        Alice.decryptSessionKey(encryptedSessionKey);

        Alice.agreeOnDecryptedSessionKey();
        Bob.agreeOnGeneratedSessionKey();
        
        String message = "Hej Alka! blablabla 1294839483929...?3342ąłżć :) #";
        byte[] ciphertext  = Alice.encrypt(message, iv);
        String plaintext = Bob.decrypt(ciphertext, iv);
        System.out.println(plaintext);
        

    }


    
}
