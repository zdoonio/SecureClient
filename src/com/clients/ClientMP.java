/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.clients;

import com.security.MPCreator;
import com.security.MPSolver;
import java.io.ByteArrayOutputStream;
import java.security.NoSuchAlgorithmException;
import javax.crypto.spec.IvParameterSpec;

/**
 *
 * @author Karol
 */
public class ClientMP implements DecEncClient {
    
    public static final int ALICE = 0;
    
    public static final int BOB = 1;
    
    public static final int NUMBER_OF_PUZZLES = 100000; 
    
    private MPCreator mpc;
    
    private MPSolver mps;
    
    private String name;
    
    public ClientMP(String name) {
        this.name = name;
    }
    

    @Override
    public byte[] encrypt(String message, IvParameterSpec iv) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public String decrypt(byte[] message, IvParameterSpec iv) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public ByteArrayOutputStream writeMessage(byte[] encryptedMessage) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public byte[] receiveMessage(ByteArrayOutputStream encryptedMessage) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
    
    
    
}
