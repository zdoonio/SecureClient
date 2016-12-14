/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.clients;

import java.io.ByteArrayOutputStream;
import javax.crypto.spec.IvParameterSpec;

/**
 * Metody zapisywania wiadomości, odczytywania, zapisywania iv i odczytywania iv.
 * @author Karol
 */
public interface WriteReceiveClient {
    
    public ByteArrayOutputStream writeMessage(byte[] encryptedMessage);
    
    public byte[] receiveMessage(ByteArrayOutputStream encryptedMessage);
    
    public ByteArrayOutputStream writeIv(IvParameterSpec iv);
    
    public IvParameterSpec receiveIv(ByteArrayOutputStream iv);
    
}
