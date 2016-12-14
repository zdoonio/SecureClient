package com.security;


import com.utils.ArrayUtils;
import com.utils.FileUtils;
import com.utils.HexUtils;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;
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
 * This class represent an entity like Bob, who picks one random puzzle 
 * from the set of puzzles given by Alice
 * and solves it, by which it agrees on a shared secret key 
 * used to encrypt and decrypt the communication.
 * 
 * @author Karol
 */
public class MPSolver implements CBCEncryptable {
    
    /**
     * The MPCreator object (Alice), which creates the puzzles.
     */
    private final MPCreator mpc;
    
    /**
     * The filename for getting the puzzles.
     */
    private final String puzzlesFile;
    
    /**
     * Session key used for encrypting the communication.
     * As with the whole application the AES128 key.
     */
    private SecretKey sessionKey;
    
    /**
     * The name of the file holding the reply to Alice.
     */
    public static final String PUBLIC_REPLY_FILE = "reply.puz";
    
    
    /**
     * Constructor with the given MPCreator object.
     * @param mpc 
     */
    public MPSolver(MPCreator mpc) {
        this.mpc = mpc;
        puzzlesFile = MPCreator.PUZZLES_FILE;
    }
    
    /**
     * Solve the puzzles. Can be seen as the main method here.
     * The solver picks on puzzle and tries different key combinations
     * always in a form (fragmentkey|zeros) to decipher the choosen puzzle.
     * If the deciphered puzzle has prefix "Puzzle#"
     * then it is well decrypted, the proper reply value is stored in a file
     * and the secret key is agreed on.
     * @throws IOException 
     */
    public void solvePuzzles() throws IOException {
        
        // get the number of puzzles stored in a file
        int fileLines = FileUtils.countLines(new File(puzzlesFile));
        
        // choose one puzzle to solve
        int lineNum = new Random().nextInt(fileLines);
        String line = FileUtils.getLine(puzzlesFile, lineNum);
 
        // parse the bytes stored in a puzzle
        byte[] parsed = ArrayUtils.parseBytes(line);
        
        // the key is not found
        boolean found = false;
        
        while(!found) {
            
            // search the key for decrypting the puzzle
            SecretKey sk = randomDecryptionKey();
            
            try {
                // decipher the puzzle
                byte[] decipher = decipherPuzzleBytes(parsed, sk);
                String decipherString = new String(decipher);
                
                // check the prefix of the puzzle and then proceed 
                if(isPrefixOk(decipherString)) { 
                    
                    found = true;
                    byte[] key = getTheSessionKeyBytes(decipherString);
                    agreeOnSessionKey(key);

                    String publicReply = getThePublicReply(decipherString);
                    writePublicReply(publicReply);
               
                }
                
            } catch (NoSuchAlgorithmException ex) {
                found = false;
            } catch (NoSuchPaddingException ex) {
                found = false;
            } catch (InvalidKeyException ex) {
                found = false;
            } catch (InvalidAlgorithmParameterException ex) {
                found = false;
            } catch (IllegalBlockSizeException ex) {
                found = false;
            } catch (BadPaddingException ex) {
                found = false;
            } catch (NumberFormatException ex) {
                found = false;
            }
        }
        
    }
    
    /**
     * Agree on a session key used for encryption 
     * and decryption of communication.
     * @param key - the bytes of the key to be agreed on
     */
    private void agreeOnSessionKey(byte[] key) {
        this.sessionKey =  new SecretKeySpec(key, 
                MPCreator.SESSION_KEY_ALGORITHM);
    }
    

    /**
     * Decipher one puzzle given in bytes. 
     * @param puzzle - the puzzle to be deciphered
     * @param sk - the SecretKey to be used when decrypting
     * @return the decrypted puzzle bytes
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws InvalidAlgorithmParameterException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException 
     */
    private byte[] decipherPuzzleBytes(byte[] puzzle, SecretKey sk) throws 
            NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, 
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        
        Cipher cipher = Cipher.getInstance(mpc.getPuzzleAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, sk, mpc.getIv());
        byte[] decipher = cipher.doFinal(puzzle);
        return decipher;

    }
    
    /**
     * Random key used for decryption of the puzzles. 
     * Has a form (fragmentkey | zeros)
     * @return the instance of SecretKey 
     */
    private SecretKey randomDecryptionKey() {
        int fragmentLen = mpc.getFragmentLen();
        int zerosLen = mpc.getZerosLen();
        byte[] fragmentKey = new byte[fragmentLen];
        SecureRandom random = new SecureRandom();
        random.nextBytes(fragmentKey);
        
        byte[] key = new byte[fragmentLen + zerosLen];
        System.arraycopy(fragmentKey, 0, key, 0, fragmentLen);
        SecretKey sk = new SecretKeySpec(key, mpc.getPuzzleKeyAlgorithm());
        return sk;
    }
    
    /**
     * Check if the prefix of a given line the same as used by the mpc object.
     * @param line - the line to be searched the prefix in
     * @return true is prefix matches the mpc prefix,  false otherwise
     */
    private boolean isPrefixOk(String line) {
        String prefix = line.substring(0, MPCreator.PREFIX.length());
        System.out.println("Prefix = " + prefix);
        return prefix
                .equals(MPCreator.PREFIX);
    }
 
    /**
     * Get the bytes from the decrypted session key (from the puzzles).
     * Because puzzles are of a form (Prefix|sessionkey|publickey) the returned
     * value is the second in this String.
     * @param decipherString - the line containing deciphered puzzle
     * @return the bytes of the session key
     * @throws NumberFormatException 
     */
    private byte[] getTheSessionKeyBytes(String decipherString) throws NumberFormatException {
        int prefixLen = MPCreator.PREFIX.length();
        int sessionKeyLen = MPCreator.SESSION_KEY_LEN;
        
        String sessionKeyBytes = decipherString
                .substring(prefixLen, prefixLen + 2*sessionKeyLen);
        try {      
            byte[] sessionkey =  HexUtils.fromHex(sessionKeyBytes);
            return sessionkey;
        } catch (NumberFormatException ex) {
            throw new NumberFormatException();
        }
        
    }
    
    /**
     * Get the public key hidden in a deciphered puzzle.
     * From the string (Prefix|sessionkey|publickey) receives the last
     * parameter.
     * @param decipherString - the deciphered line to be taken the value from
     * @return - the public key (public reply)
     */
    private String getThePublicReply(String decipherString) {
        int prefixLen = MPCreator.PREFIX.length();
        int sessionKeyLen = MPCreator.SESSION_KEY_LEN;
        
        String publicReply = decipherString
                .substring(prefixLen + 2*sessionKeyLen, decipherString.length());
        
        return publicReply;
    }
    
    /**
     * Write the public reply to a file.
     * @param reply - the reply to be written
     */
    private void writePublicReply(String reply) {
        PrintWriter pw = null;
        try {
            pw = new PrintWriter(new File(PUBLIC_REPLY_FILE));
            pw.println(reply);
            pw.close();
        } catch (FileNotFoundException ex) {
            Logger.getLogger(MPSolver.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            pw.close();
        }
    }

    /**
     * the overriden encrypt from interface CBCEncryptable
     * @param plaintext
     * @param iv
     * @return 
     */
    public byte[] encrypt(String plaintext, IvParameterSpec iv) {
        try {
            Cipher cipher = Cipher.getInstance(MPCreator.ENC_DEC_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, sessionKey, iv);
            byte[] encryption = cipher.doFinal(plaintext.getBytes());
            return encryption;
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(MPSolver.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(MPSolver.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(MPSolver.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidAlgorithmParameterException ex) {
            Logger.getLogger(MPSolver.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(MPSolver.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(MPSolver.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    /**
     * The decrypt overriding the method from CBCEncryptable interface.
     * @param ciphertext - ciphertext to be decrypted
     * @param iv - the iv to be used when decrypting
     * @return the decrypted text
     */
    public String decrypt(byte[] ciphertext, IvParameterSpec iv) {
         try {
            Cipher cipher = Cipher.getInstance(MPCreator.ENC_DEC_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, sessionKey, iv);
            byte[] decryption = cipher.doFinal(ciphertext);
            return new String(decryption);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(MPSolver.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(MPSolver.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(MPSolver.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidAlgorithmParameterException ex) {
            Logger.getLogger(MPSolver.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(MPSolver.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(MPSolver.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
    
    
        
    
    /**
     * To see how it works.
     * @param args 
     */
    public static void main(String[] args) {
        try {
            MPCreator mpbc = new MPCreator(10000, EnabledCiphers.AES_CBC);
            mpbc.createPuzzles();
            MPSolver mpbs = new MPSolver(mpbc);
            mpbs.solvePuzzles();
            mpbc.agreeOnKey(PUBLIC_REPLY_FILE);
            
            String message = "hey, how are you, Joao. No I havent seen the Fast and furious,"
                    + "any episode actually. zamknij mordkę, chociaż wszystko się udało!";
            
            IvParameterSpec iv = IvGenerator.generateIV(IvGenerator.AES_BLOCK_SIZE);
            
            byte[] encrypt = mpbc.encrypt(message, iv);
                   
            String decrypt = mpbs.decrypt(encrypt, iv);
                   
            System.out.println(decrypt);
            
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(MPSolver.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(MPSolver.class.getName()).log(Level.SEVERE, null, ex);
        }  catch (NoSuchPaddingException ex) {
            Logger.getLogger(MPSolver.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(MPSolver.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(MPSolver.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(MPSolver.class.getName()).log(Level.SEVERE, null, ex);
        }  catch (InvalidAlgorithmParameterException ex) {
            Logger.getLogger(MPSolver.class.getName()).log(Level.SEVERE, null, ex);
        }
        
    }
    
}
