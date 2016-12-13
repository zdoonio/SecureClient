/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.security;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.spec.IvParameterSpec;

/**
 *
 * @author Karol
 * Static for now, can be generated 
 */
public class IvGenerator {
    
    /**
     * AES block size in bytes.
     */
    public static final int AES_BLOCK_SIZE = 128 / 8;
    
    public static IvParameterSpec generateIV(int blockSize) {
        try {
            SecureRandom randomSecureRandom = SecureRandom.getInstance("SHA1PRNG");
            byte[] ivGen = new byte[blockSize];
            randomSecureRandom.nextBytes(ivGen);
            
            IvParameterSpec ivParams = new IvParameterSpec(ivGen);
            return ivParams;
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(DiffieHellman.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
    
}
