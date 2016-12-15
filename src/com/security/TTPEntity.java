/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.security;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
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
 * TODO : make encryption and decryption of messages
 */
public class TTPEntity {
    
    public enum algorithms {DES, DESede, AES};
    public enum modes {CBC, ECB};
    public final int sessionKeyLen;
    public final String cipherAlgorithm;
    public final String cipherMode;
    
    public final String ciphModPad;
    
    /**
     * Distributed key used for encrypting or decrypting 
     * the secret key used for communication. 
     * Currently only AES key. 
     */
    private SecretKey distrKey;
    
    /**
     * Generated session key. Alice's key.
     */
    private SecretKey generatedKey;
    
    /**
     * Decrypted session key. Bob's key.
     */
    private SecretKey decryptedKey;
    
    /**
     * Final session key agreed on by two entities, 
     * used for encryption and decryption of communication.
     */
    private SecretKey sessionKey;
    
    /**
     * Create an instance of TTPEntity with the algorithm and mode
     * for decrypting and encrypting of messages - communication between
     * this and another TTPEntity instance.
     * 
     * @param algorithm 
     * @param mode 
     */
    public TTPEntity(algorithms algorithm, modes mode) {
        switch(algorithm) {
            case DES :
                cipherAlgorithm = "DES";
                sessionKeyLen = 68 / 8;
                break;
            case DESede :
                cipherAlgorithm = "DESede";
                sessionKeyLen = 168 / 8;
                break;
            default :
                cipherAlgorithm = "AES";
                sessionKeyLen = 128 / 8;
                break;
        }
        
        if(mode.equals(modes.CBC)) {
            cipherMode = "CBC";
        } else {
            cipherMode = "ECB";
        }
        
        ciphModPad = cipherAlgorithm + "/" + cipherMode + "/PKCS5Padding";
    }
    
    /**
     * To be used only with creating TTP instance.
     * @param key
     */
    protected void setDistrKey(SecretKey key) {
        distrKey = key;
    }
    
    /**
     * Generation of a session key.
     * If an instance is Alice, she can generate 
     * the session key and then agree on it. 
     * The session key depends on the algorithm chosen 
     * for decryption and encryption of messages.
     */
    public void generateAndAgreeOnSessionKey() {
        SecretKey key = generateKey(sessionKeyLen, cipherAlgorithm);
        generatedKey = key;
        agreeOnGeneratedKey(generatedKey);
    }
    
    
    /**
     * Encryption of a session key. 
     * This to be used only when an instance is Alice.
     * This encyption should be send to TTP.
     * 
     * @param iv - initialization vector, for the algorithm used is AES in CBC mode.
     * @return
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws InvalidAlgorithmParameterException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException 
     */
    public byte[] encryptSessionKey(IvParameterSpec iv) throws 
            NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, 
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, distrKey, iv);
        byte[] sessionKeyByte = cipher.doFinal(sessionKey.getEncoded());
        return sessionKeyByte;
    }
    
    
    /**
     * Decryption of the session key.
     * This to be used only when an instance is Bob.
     * Encryption is received from TTP.
     * Then, because encrypted is session key, after decryption
     * instance agrees on the decrypted session key.
     * 
     * @param sessionKeyDec - the session key to be decrypted
     * @param iv - initialization vector, for the algortihm used is AES in CBC mode
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws InvalidAlgorithmParameterException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException 
     */
    public void decryptAndAgreeOnSessionKey(byte[] sessionKeyDec, IvParameterSpec iv) throws 
            NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, 
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, distrKey, iv);
        byte[] decrypted = cipher.doFinal(sessionKeyDec);
        SecretKey sk = new SecretKeySpec(decrypted, cipherAlgorithm);
        decryptedKey = sk;
        agreeOnDecryptedKey(decryptedKey);
    }
    
    private void agreeOnGeneratedKey(SecretKey key) {
        sessionKey = key;
    }
    
    private void agreeOnDecryptedKey(SecretKey key){
        sessionKey = key;
    }

    
    /**
     * Util for generating the random key 
     * of given keyLen and with given algorithm.
     * @param keyLen - the length of the key to be generated
     * @param algorithm - string representing algorithm to be used for generation
     * @return generated SecretKey
     */
    private static SecretKey generateKey(int keyLen, String algorithm) {
        SecureRandom random = new SecureRandom();
        byte[] keyByte = new byte[keyLen];
        random.nextBytes(keyByte);
        SecretKey key = new SecretKeySpec(keyByte, algorithm);
        return key;
    }
    
    
    
    public byte[] encryptMessage(String message) throws 
            NoSuchAlgorithmException, NoSuchPaddingException, 
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException, 
            InvalidAlgorithmParameterException {
        byte[] ciphertext = encryptMessage(message, null);
        return ciphertext;
        
    }
    
    public byte[] encryptMessage(String message, IvParameterSpec iv) throws 
            NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, 
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(ciphModPad);
        if(iv == null) cipher.init(Cipher.ENCRYPT_MODE, sessionKey);
        else cipher.init(Cipher.ENCRYPT_MODE, sessionKey, iv); 
        
        byte[] ciphertext = cipher.doFinal(message.getBytes());
        return ciphertext;
    }
    
    public String decryptMessage(byte[] ciphertext) throws 
            NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, 
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        String decryption = decryptMessage(ciphertext, null);
        return decryption;
    }
    
    public String decryptMessage(byte[] ciphertext, IvParameterSpec iv) throws 
            NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, 
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher =  Cipher.getInstance(ciphModPad);
        if(iv == null) cipher.init(Cipher.DECRYPT_MODE, sessionKey);
        else cipher.init(Cipher.DECRYPT_MODE, sessionKey, iv);
        
        byte[] messageBytes = cipher.doFinal(ciphertext);
        return new String(messageBytes);
    }
    
    
    
    
    
}
