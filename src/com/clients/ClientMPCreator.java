/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.clients;

import com.security.MPCreator;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

/**
 *
 * @author Karol
 */
public class ClientMPCreator implements ChatClient {
    
    private int numberOfPuzzles;
    
    private String algorithm;
    
    private MPCreator mpc;
    
    private final String name;
    
    private final WriteReceiveClient wrc;
    
    public ClientMPCreator(String name) {
        this.name = name;
        wrc = new WriteReceiveClientImpl();
    }
    
    public void init(int numberOfPuzzles, String algorithm) throws NoSuchAlgorithmException {
        this.numberOfPuzzles = numberOfPuzzles;
        this.algorithm = algorithm;
        mpc = new MPCreator(this.numberOfPuzzles, this.algorithm);
    }
    
    public void createPuzzles(String filename) throws 
            FileNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, 
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, InvalidAlgorithmParameterException {
        mpc.createPuzzles(filename);
    }
    
    public String getPuzzleFileName() {
        return mpc.getPuzzleFileName();
    }
    
    public IvParameterSpec getPuzzleIv() {
        return mpc.getIv();
    }
    
    public String puzzleAlgorithm() {
        return mpc.getPuzzleAlgorithm();
    }
    
    public String secretKeyAlgorithm() {
        return MPCreator.SESSION_KEY_ALGORITHM;
    }
    
    

    @Override
    public byte[] encrypt(String message, IvParameterSpec iv) {
        return mpc.encrypt(message, iv);
    }

    @Override
    public String decrypt(byte[] message, IvParameterSpec iv) {
        return mpc.decrypt(message, iv);
    }

    @Override
    public ByteArrayOutputStream writeMessage(byte[] encryptedMessage) {
        return wrc.writeMessage(encryptedMessage);
    }

    @Override
    public byte[] receiveMessage(ByteArrayOutputStream encryptedMessage) {
        return wrc.receiveMessage(encryptedMessage);
    }

    @Override
    public ByteArrayOutputStream writeIv(IvParameterSpec iv) {
        return wrc.writeIv(iv);
    }

    @Override
    public IvParameterSpec receiveIv(ByteArrayOutputStream iv) {
        return wrc.receiveIv(iv);
    }

    public int getFragmentKeyLen() {
        return mpc.getFragmentLen();
    }
    
    public int getZerosKeyLen() {
        return mpc.getZerosLen();
    } 
    
    public String getPuzzleAlgorithm() {
        return mpc.getPuzzleAlgorithm();
    }
    
    public String getSecretKeyAlgorithm() {
        return mpc.getPuzzleKeyAlgorithm();
    }
    
    public String getPuzzlesFilename() {
        return mpc.getPuzzleFileName();
    }
    
    public void agreeOnKey(String filename) {
        mpc.agreeOnKey(filename);
    }
    
    
    
}
