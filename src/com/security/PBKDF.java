package com.security;


import com.utils.HexUtils;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Class consists of static methods for deriving the key based on passwords given by the user. 
 * It enables to use different hash functions, namely: SHA1, SHA256 and MD5,
 * with their corresponding algorithms provided by SecretKeyFactory and PBEKeySpec.
 * Ideally the user can derive the hash (the key) of desired length 
 * so that he can encrypt and decrypt the communication using cipher algorithms of his choice.
 * The final hash has the form number_of_iterations:salt:derived_key, so that whenever it is needed
 * each of the parts can be obtained.
 * 
 * @author Karol
 */
public class PBKDF {
    
    /**
     * Algorithm used with the SHA1 hash function.
     */
    public static final String SHA1_ALGORITHM = "PBKDF2WithHmacSHA1";
    
    /**
     * Algorithm used with SHA256 hash function.
     */
    public static final String SHA256_ALGORITHM = "PBEWithHmacSHA256AndAES_128";
    
    /**
     * Algorithm used with MD5 hash function.
     */
    public static final String MD5_ALGORITHM = "PBEWithMD5AndDES";
    
    /**
     * The desired length of salt in bytes.
     */
    public static final int SALT_BYTES = 16;
    
    
    /**
     * Number of iterations for PBKDF. 
     * 4096 is recommended by 2005 Kerberos standard.
     */
    public static final int PBKDF2_ITERATIONS = 4096;

    /**
     * Index of iterations in the final hash value.
     */
    public static final int ITERATION_INDEX = 0;
    
    /**
     * Index of salt in the final hash value.
     */
    public static final int SALT_INDEX = 1;
    
    /**
     * Index of key in the final hash value.
     */
    public static final int PBKDF2_INDEX = 2;
    
    
    
    /**
     * Returns a salted PBKDF2 hash of the password.
     *
     * @param   password    the password to hash
     * @param   algorithm
     * @param   bytes       desired length for the hash in bytes
     * @return              a salted PBKDF2 hash of the password
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.security.spec.InvalidKeySpecException
     */
    public static String createHash(String password, String algorithm, int bytes)
        throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        return createHash(password.toCharArray(), algorithm, bytes);
    }

    /**
     * Returns a salted PBKDF2 hash of the password.
     *
     * @param   password    the password to hash
     * @param   algorithm
     * @param   bytes       desired length of the hash in bytes
     * @return              a salted PBKDF2 hash of the password
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.security.spec.InvalidKeySpecException
     */
    public static String createHash(char[] password, String algorithm, int bytes)
        throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        // Generate salt
        byte[] salt = generateSalt();
        // Hash the password
        byte[] hash = pbkdf(password, salt, PBKDF2_ITERATIONS, bytes, algorithm);
        // format iterations:salt:hash
        return PBKDF2_ITERATIONS + ":" + HexUtils.toHex(salt) + ":" +  HexUtils.toHex(hash);
    }
    
    public static String createKey(String password, int bytes, byte[] salt) throws 
            InvalidKeySpecException, NoSuchAlgorithmException {
        byte[] hash = pbkdf(password.toCharArray(), salt, PBKDF2_ITERATIONS, bytes, SHA1_ALGORITHM);
        return HexUtils.toHex(hash);
    }
    
    /**
     * Returns a generated random salt.
     * 
     * @return salt 
     */
    private static byte[] generateSalt() 
    {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[SALT_BYTES];
        random.nextBytes(salt);
        return salt;
    }

    /**
     * Validates a password using a hash.
     *
     * @param   password    the password to check
     * @param   goodHash    the hash of the valid password
     * @param   algorithm
     * @return              true if the password is correct, false if not
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.security.spec.InvalidKeySpecException
     */
    public static boolean validatePassword(String password, String goodHash, String algorithm)
        throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        return validatePassword(password.toCharArray(), goodHash, algorithm);
    }

    /**
     * Validates a password using a hash.
     *
     * @param   password    the password to check
     * @param   goodHash    the hash of the valid password
     * @param   algorithm
     * @return              true if the password is correct, false if not
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.security.spec.InvalidKeySpecException
     */
    public static boolean validatePassword(char[] password, String goodHash, String algorithm)
        throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        // Decode the hash into its parameters
        String[] params = goodHash.split(":");
        int iterations = Integer.parseInt(params[ITERATION_INDEX]);
        byte[] salt = HexUtils.fromHex(params[SALT_INDEX]);
        byte[] hash = HexUtils.fromHex(params[PBKDF2_INDEX]);
        // Compute the hash of the provided password, using the same salt, 
        // iteration count, and hash length
        byte[] testHash = pbkdf(password, salt, iterations, hash.length, algorithm);
        // Compare the hashes in constant time. The password is correct if
        // both hashes match.
        return slowEquals(hash, testHash);
    }

    /**
     * Compares two byte arrays in length-constant time. This comparison method
     * is used so that password hashes cannot be extracted from an on-line 
     * system using a timing attack and then attacked off-line.
     * 
     * @param   a       the first byte array
     * @param   b       the second byte array 
     * @return          true if both byte arrays are the same, false if not
     */
    private static boolean slowEquals(byte[] a, byte[] b)
    {
        int diff = a.length ^ b.length;
        for(int i = 0; i < a.length && i < b.length; i++)
            diff |= a[i] ^ b[i];
        return diff == 0;
    }

    /**
     *  Computes the PBKDF2 hash of a password.
     *
     * @param   password    the password to hash.
     * @param   salt        the salt
     * @param   iterations  the iteration count (slowness factor)
     * @param   bytes       the length of the hash to compute in bytes
     * @param   algorithm   the algorithm to be used for creating the hash
     * @return              the PBDKF2 hash of the password
     */
    private static byte[] pbkdf(char[] password, byte[] salt, int iterations, int bytes, String algorithm)
        throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, bytes * 8);
        SecretKeyFactory skf = SecretKeyFactory.getInstance(algorithm);
        return skf.generateSecret(spec).getEncoded();
    }
    
    /**
     * For testing the behaviour.
     * @param args 
     */
    public static void main(String[] args) {
        try {
            String password = "Tomojehaslo1245";
            String algorithm = SHA1_ALGORITHM;
            
            // Np. jeśli chcemy mieć hasło do encryptowania za pomocą AES128.
            int keyLen = 128 / 8;
            
            String hash = PBKDF.createHash(password, algorithm, keyLen);
            System.out.println(hash);
            
            boolean validate = validatePassword(password, hash, algorithm);
            
            System.out.println(validate);
            
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(PBKDF.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeySpecException ex) {
            Logger.getLogger(PBKDF.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
}
