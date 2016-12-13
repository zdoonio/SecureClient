
package com.security;

import javax.crypto.spec.IvParameterSpec;

/**
 *
 * @author Karol
 */
public interface CBCEncryptable {
    
    public byte[] encrypt(String plaintext, IvParameterSpec iv);
    public String decrypt(byte[] ciphertext, IvParameterSpec iv);
    
    
}
