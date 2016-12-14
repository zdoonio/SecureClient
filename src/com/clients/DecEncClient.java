/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.clients;

import java.io.ByteArrayOutputStream;
import javax.crypto.spec.IvParameterSpec;

/**
 *
 * @author Karol
 */
public interface DecEncClient {
    
    public byte[] encrypt(String message, IvParameterSpec iv);
    
    public String decrypt(byte[] message, IvParameterSpec iv);

    public ByteArrayOutputStream writeMessage(byte[] encryptedMessage);
    
    public byte[] receiveMessage(ByteArrayOutputStream encryptedMessage);
    
}
