package com.clients;

import com.security.MPSolver;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import javax.crypto.spec.IvParameterSpec;

/**
 * The solver of the MerklePuzzle instance. 
 * @author Karol
 */
public class ClientMPSolver implements ChatClient {
    
    private final MPSolver mps;
    
    private final WriteReceiveClient wrc;
    
    private final String name;
    
    public ClientMPSolver(String name) {
        this.name = name;
        mps = new MPSolver();
        wrc = new WriteReceiveClientImpl();
    }
    
    public ClientMPSolver setReplyFilename(String replyFilename) {
        mps.setReplyFilename(replyFilename);
        return this;
    }
    
    public ClientMPSolver setPuzzleFilename(String filename) {
        mps.setPuzzleFilename(filename);
        return this;
    }
    
    public ClientMPSolver setPuzzleAlgorithm(String puzzleAlgorithm) {
        mps.setPuzzleAlgorithm(puzzleAlgorithm);
        return this;
    }
    
    public ClientMPSolver setSecretKeyAlgorithm(String secretKeyAlgorithm) {
        mps.setSecretKeyAlgorithm(secretKeyAlgorithm);
        return this;
    }
    
    public ClientMPSolver setIv(IvParameterSpec iv) {
        mps.setIv(iv);
        return this;
    }
    
    public ClientMPSolver setFragmentKeylen(int fragmentKeyLen) {
        mps.setFragmentKeylen(fragmentKeyLen);
        return this;
    }
    
    public ClientMPSolver setZerosKeylen(int zerosLen) {
        mps.setZerosKeylen(zerosLen);
        return this;
    }
    
    public String getReplyFilename() {
        return mps.getReplyFilename();
    }
    
    public void solvePuzzles() throws IOException {
        mps.solvePuzzles();
    }

    @Override
    public byte[] encrypt(String message, IvParameterSpec iv) {
        return mps.encrypt(message, iv);
    }

    @Override
    public String decrypt(byte[] message, IvParameterSpec iv) {
        return mps.decrypt(message, iv);
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
    
    
    
}
