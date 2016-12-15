/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.security;

import com.security.TTPEntity.algorithms;
import com.security.TTPEntity.modes;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
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
 *
 * @author Karol
 */
public class TTP {
    
    /**
     * Alice AES key. 
     * Used for decrypting the encrypted session key received from Alice.
     */
    private final SecretKey aliceKey;
    
    /**
     * Bob AES key. 
     * Used for ecnrypting the session key, before sending to Bob.
     */
    private final SecretKey bobKey;
    
    /**
     * Session key used for encryption of messages.
     * This key can be any Cipher key.
     */
    private SecretKey sessionKey;
    
    
    
    public TTP(TTPEntity Alice, TTPEntity Bob) {
        Alice.setDistrKey(aliceKey = generateKey());
        Bob.setDistrKey(bobKey = generateKey());
    }
    
    public void decryptSessionKey(byte[] ciphertext, IvParameterSpec iv) throws 
            NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, 
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, aliceKey, iv);
        byte[] sessionKeyByte = cipher.doFinal(ciphertext);
        sessionKey = new SecretKeySpec(sessionKeyByte, "AES");
    }
    
    public byte[] encryptSessionKey(IvParameterSpec iv) throws 
            NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, bobKey, iv);
        byte[] cipherByte = cipher.doFinal(sessionKey.getEncoded());
        return cipherByte;
    }
    
    /**
     * Generates AES128 key used for encryption of secret key.
     * This is key generated for both Alice and Bob, separately.
     * 
     * @return 
     */
    private SecretKey generateKey() {
        SecureRandom random = new SecureRandom();
        byte[] key = new byte[128 / 8];
        random.nextBytes(key);
        SecretKey sk = new SecretKeySpec(key, "AES");
        return sk;
    }
    
    public static void main(String[] args) {
        
        try {
            algorithms algorithm = algorithms.AES;
            modes mode = modes.CBC;
            
            int aesBlockSize = Cipher.getInstance("AES").getBlockSize();
            
            IvParameterSpec iv = IvGenerator.generateIV(aesBlockSize);
            
            TTPEntity Alice = new TTPEntity(algorithm, mode);
            TTPEntity Bob = new TTPEntity(algorithm, mode);
            
            TTP ttp = new TTP(Alice, Bob);
            
            // Alice generates the key and agress on it.
            Alice.generateAndAgreeOnSessionKey();
            
            // Alice decrypt the key and sends it to TTP
            byte[] encryptSessionKey = Alice.encryptSessionKey(iv);
            
            // TTP decrypts it then encrypts with bob key and sends to Bob.
            ttp.decryptSessionKey(encryptSessionKey, iv);
            byte[] encryptSessionKeyBob = ttp.encryptSessionKey(iv);
            
            // Bob decrypts it and agress on it
            Bob.decryptAndAgreeOnSessionKey(encryptSessionKeyBob, iv);
            
            // Now they both have the same session key. 
            // We can encrypt and decrypt a message.
            String message = "how are you Alice? ";
            
            IvParameterSpec ivM = IvGenerator.generateIV(aesBlockSize);
            
            byte[] encrypted = Bob.encryptMessage(message, ivM);
            String decrypted = Alice.decryptMessage(encrypted, ivM);
            
            System.out.println(decrypted);
            
            
                    
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(TTP.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(TTP.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(TTP.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidAlgorithmParameterException ex) {
            Logger.getLogger(TTP.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(TTP.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(TTP.class.getName()).log(Level.SEVERE, null, ex);
        }
        
    }
    
}
