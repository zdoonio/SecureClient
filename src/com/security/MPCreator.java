package com.security;

import com.utils.FileUtils;
import com.utils.HexUtils;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
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
public class MPCreator implements CBCEncryptable {
    
    // Below the constants for encryption of communication
    
    /**
     * Algorithm used for encyption of communication between two entities.
     * As with the whole application, symmetric encryption done with AES/CBC/PKCS5Padding.
     */
    public static final String ENC_DEC_ALGORITHM = EnabledCiphers.AES_CBC;
    
    /**
     * Algorithm that is used for creating a secret key used 
     * for encryption and decryption of communication.
     */
    public static final String SESSION_KEY_ALGORITHM = EnabledCiphers.AES;
    
    /**
     * Algorithm for session key in bytes.
     */
    public static final int SESSION_KEY_LEN = EnabledCiphers.AES_KEY_LEN_BYTES;
    
    // Below the constants for the puzzles making 
    
    // when using DES encryption.
    /**
     * The length in bytes of the key used for encrypting the puzzles.
     */
    public static final int DES_KEY_FRAGMENT_LEN = 24 / 8;   
    
    /**
     * The length in bytes of zeros in the key used for encrypting the puzzles.
     */
    public static final int DES_ZEROS_LEN = 40 / 8;
    
    // when using 3DES encryption
    /**
     * The length in bytes of the key used encrypting the puzzles.
     */
    public static final int DES_EDE_KEY_FRAGMENT_LEN = 56 / 8;
    
    /**
     * The length in bytes of the zeros in the key used for encrypting the puzzles.
     */
    public static final int DES_EDE_ZEROS_LEN = 136 / 8;
    
    // when using AES128 
    /**
     * The length in bytes of the key used for encrypting the puzzles.
     */
    public static final int AES_KEY_FRAGMENT_LEN = 32 / 8;
    
    /**
     * The length in bytes of the zeros in the key for encrypting the puzzles. 
     */
    public static final int AES_ZEROS_LEN = 96 / 8;
    
    /**
     * The prefix to be used for making a puzzle.
     */
    public static final String PREFIX = "Puzzle#";
    
    /**
     * The name of the file for storing the puzzles.
     */
    public static final String PUZZLES_FILE = "puzzles.puz";
    
    // the object fields
    
    /**
     * The number of puzzles to be created. 
     */
    private final int numberOfPuzzles;
    
    /**
     * The algorithm to be used for creating the puzzles.
     */
    private final String puzzleAlgorithm;
    
    /**
     * The algoritm to be used for creating the key for encryption of the puzzles.
     */
    private final String puzzleKeyAlgorithm;
    
    /**
     * The length in bytes of zeros in the keys used for encrypting the puzzles.
     */
    private final int zerosLen;
    
    /**
     * The length in bytes of the fragment of the key used for encryption of the puzzles.
     */
    private final int fragmentKeyLen;
    
    /**
     * The name of the file for storing the plain generated puzzles. 
     * Just for the creator.
     */
    private static final String PRIVATE_PUZZLES_FILE = "private.puz";    
    
    /**
     * The session key finally agreed on by the instance.
     * Used for encrypting and decrypting the communication between this 
     * object and MerklePuzzleSolver object.
     */
    private SecretKey sessionKey;
    
    /**
     * The random number generator.
     */
    private final SecureRandom secureRandom;

    /**
     * Iv to be created when encrypting the puzzles.
     */
    public final IvParameterSpec iv;
    
    

    
    /**
     * 
     * @param numberOfPuzzles - the number of puzzles to be created
     * @param puzzleAlgorithm - either AES_CBC, DES_CBC or DESede_CBC, to be used for encrypting the puzzles.
     * @throws java.security.NoSuchAlgorithmException if the puzzleAlgorithm is not one of mentioned above
     */
    public MPCreator(int numberOfPuzzles, String puzzleAlgorithm) 
            throws NoSuchAlgorithmException {
        
        this.numberOfPuzzles = numberOfPuzzles;
        this.puzzleAlgorithm = puzzleAlgorithm;
        this.secureRandom = new SecureRandom();
        
        
        if( puzzleAlgorithm.equals(EnabledCiphers.AES_CBC)) {
            zerosLen = AES_ZEROS_LEN;
            fragmentKeyLen = AES_KEY_FRAGMENT_LEN;
            iv = IvGenerator.generateIV(IvGenerator.AES_BLOCK_SIZE);
            puzzleKeyAlgorithm = EnabledCiphers.AES;
            
        } else if ( puzzleAlgorithm.equals(EnabledCiphers.DES_CBC)) {
            zerosLen = DES_ZEROS_LEN;
            fragmentKeyLen = DES_KEY_FRAGMENT_LEN;
            iv = IvGenerator.generateIV(IvGenerator.DES_BLOCK_SIZE);
            puzzleKeyAlgorithm = EnabledCiphers.DES;
        
        } else if ( puzzleAlgorithm.equals(EnabledCiphers.DES_EDE_CBC)) {
            zerosLen = DES_EDE_ZEROS_LEN;
            fragmentKeyLen = DES_EDE_KEY_FRAGMENT_LEN;
            iv = IvGenerator.generateIV(IvGenerator.DES_BLOCK_SIZE);
            puzzleKeyAlgorithm = EnabledCiphers.DES_EDE;
        
        } else throw new NoSuchAlgorithmException("Algorithm is not one of AES, DES or DESede!"); 
    }
    
    /**
     * Creates the puzzles and saves them in the file.
     * @throws java.io.FileNotFoundException
     * @throws java.security.NoSuchAlgorithmException
     * @throws javax.crypto.NoSuchPaddingException
     * @throws java.security.InvalidKeyException
     * @throws javax.crypto.BadPaddingException
     * @throws javax.crypto.IllegalBlockSizeException
     * @throws java.io.UnsupportedEncodingException
     * @throws java.security.InvalidAlgorithmParameterException
     */
    public void createPuzzles() throws FileNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, InvalidAlgorithmParameterException {
        
        File privatePuzzlesFile = new File(PRIVATE_PUZZLES_FILE);
        PrintWriter pw = new PrintWriter(privatePuzzlesFile);
        
        // Create the puzzles.
        for(int i = 0; i < numberOfPuzzles; i++) {
            String line = PREFIX + HexUtils.toHex(randomAesKey()) + HexUtils.toHex(intToByte(i));
            pw.println(line);
        }
        pw.close();
        
        File puzzlesFile = new File(PUZZLES_FILE);
        PrintWriter pw2 = new PrintWriter(puzzlesFile);
        
        for(int i = 0; i < numberOfPuzzles; i++) {
            int j = (int) (Math.random() * numberOfPuzzles);
            String line = FileUtils.getLine(PRIVATE_PUZZLES_FILE, j);
            pw2.println(Arrays.toString(encryptLine(line)));
        }
        
        pw2.close();
        
    }
    
    private byte[] encryptLine(String line) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, InvalidAlgorithmParameterException {
        
        byte[] fragmentKey = new byte[fragmentKeyLen];
        secureRandom.nextBytes(fragmentKey);
        byte[] key = new byte[fragmentKeyLen + zerosLen];
        System.arraycopy(fragmentKey, 0, key, 0, fragmentKeyLen);
        SecretKey sk = new SecretKeySpec(key, puzzleKeyAlgorithm);
        
        byte[] lineByte = line.getBytes();
        Cipher cipher = Cipher.getInstance(puzzleAlgorithm);
        cipher.init(Cipher.ENCRYPT_MODE, sk, iv);
         
        byte[] doFinal = cipher.doFinal(lineByte);
        return doFinal;
        
    }
    
    public void agreeOnKey(String filename) {
        
        String hex = FileUtils.getLine(filename, 0);
        byte[] bytes = HexUtils.fromHex(hex);
        int linenumber = byteToInt(bytes);
        
        String line = FileUtils.getLine(PRIVATE_PUZZLES_FILE, linenumber);
        
        byte[] key = HexUtils.fromHex(line.substring(PREFIX.length(),
                PREFIX.length() + 2*SESSION_KEY_LEN));
        this.sessionKey = new SecretKeySpec(key, SESSION_KEY_ALGORITHM);
        
    }
    
    
    private byte[] randomAesKey() {
        byte[] key = new byte[SESSION_KEY_LEN];
        secureRandom.nextBytes(key);
        return key;
    }
    
    private byte[] intToByte(int i) {
        byte[] bytes = ByteBuffer
                .allocate(SESSION_KEY_LEN)
                .putInt(i)
                .array();
        
        return bytes;
    }
    
    private int byteToInt(byte[] b) {
        return ByteBuffer.wrap(b).getInt();
    }
    
    public int getFragmentLen() {
        return this.fragmentKeyLen;
    }
    
    public int getZerosLen() {
        return this.zerosLen;
    }
    
    public String getPuzzleKeyAlgorithm() {
        return this.puzzleKeyAlgorithm;
    }
    
    public String getPuzzleAlgorithm() {
        return this.puzzleAlgorithm;
    }
    
    public IvParameterSpec getIv(){
        return this.iv;
    }
    
 
    public byte[] encrypt(String plaintext, IvParameterSpec iv) {
        try {
            Cipher cipher = Cipher.getInstance(ENC_DEC_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, sessionKey, iv);
            byte[] encryption = cipher.doFinal(plaintext.getBytes());
            return encryption;
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(MPCreator.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(MPCreator.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(MPCreator.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidAlgorithmParameterException ex) {
            Logger.getLogger(MPCreator.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(MPCreator.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(MPCreator.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    public String decrypt(byte[] ciphertext, IvParameterSpec iv) {
        try {
            Cipher cipher = Cipher.getInstance(ENC_DEC_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, sessionKey, iv);
            byte[] decryption = cipher.doFinal(ciphertext);
            return new String(decryption);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(MPCreator.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(MPCreator.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(MPCreator.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidAlgorithmParameterException ex) {
            Logger.getLogger(MPCreator.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(MPCreator.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(MPCreator.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }   
    
    public static void main(String[] args) throws NoSuchAlgorithmException, FileNotFoundException {
        
        try {
            MPCreator mpbc = new MPCreator(134, EnabledCiphers.DES_EDE_CBC);
            mpbc.createPuzzles();
            
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(MPCreator.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(MPCreator.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(MPCreator.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(MPCreator.class.getName()).log(Level.SEVERE, null, ex);
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(MPCreator.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidAlgorithmParameterException ex) {
            Logger.getLogger(MPCreator.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        MPCreator mpbc = new MPCreator(123, EnabledCiphers.DES_EDE_CBC);
        
        
    }

    
    
    
    
    
    
    
    
    
    
    
    
    
}
