package com.security;

/**
 * Class consists of static fields containing the available 
 * ciphers and corresponding key length.
 * To be used when encrypting, decrypting, agreeing on key etc.
 * @author Karol
 */
public class EnabledCiphers {
    
    public static final String AES = "AES";
    
    public static final String DES = "DES";
    
    public static final String DES_EDE = "DESede";
    
    public static final String AES_CBC = "AES/CBC/PKCS5Padding";
    
    public static final String AES_ECB = "AES/ECB/PKCS5Padding";
    
    public static final String DES_CBC = "DES/CBC/PKCS5Padding";
    
    public static final String DES_ECB = "DES/ECB/PKCS5Padding";
    
    public static final String DES_EDE_CBC = "DESede/CBC/PKCS5Padding";
    
    public static final String DES_EDE_ECB = "DESede/ECB/PKCS5Padding";
    
    public static final int AES_KEY_LEN = 128;
    
    public static final int AES_KEY_LEN_BYTES = 128 / 8;
    
    public static final int DES_KEY_LEN = 64;
    
    public static final int DES_KEY_LEN_BYTES = 64 / 8;
    
    public static final int DES_EDE_KEY_LEN = 168;
    
    public static final int DES_EDE_KEY_LEN_BYTES = 168 / 8;
    
    public static final String CBC_MODE = "CBC";
    
    public static final String ECB_MODE = "ECB";
    
}
