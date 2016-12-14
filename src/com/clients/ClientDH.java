
package com.clients;

import com.security.DiffieHellman;
import com.security.IvGenerator;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.IvParameterSpec;

/**
 *
 * @author Karol
 */
public class ClientDH implements ChatClient {
    
    /**
     * The name of this Client.
     */
    public final String name;
    
    private final DiffieHellman dh;
    
    private final WriteReceiveClient wrc;
    
    private PublicKey myPublicKey;
    
    private PrivateKey myPrivateKey;
    
    public final String PUBLIC_KEY_FILE;
    
    public final String SIGNATURE_FILE;
    
    public ClientDH(String name) throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
        this.name = name;
        dh = new DiffieHellman();
        dh.generateKeys();
        wrc = new WriteReceiveClientImpl();
        PUBLIC_KEY_FILE = "dh/" + name + "DH" + ".suepk";
        SIGNATURE_FILE = "dh/" + name + "DH" + ".sig";
        initSigning();
        
    }
    
    public void receivePublicKey(ByteArrayOutputStream boas, String signatureFile, String dsaKeyFile) throws 
            IOException, ClassNotFoundException, FileNotFoundException, NoSuchAlgorithmException, 
            NoSuchProviderException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        
        if(verifyPublicKeySignature(boas, signatureFile, dsaKeyFile)) {
            ByteArrayInputStream bais = new ByteArrayInputStream(boas.toByteArray());
            BufferedInputStream bis = new BufferedInputStream(bais);
            try (ObjectInputStream ois = new ObjectInputStream(bis)) {
                Object obj = ois.readObject();
                if( !(obj instanceof DHPublicKey) ) throw new ClassNotFoundException();
                else {
                    dh.receivePublicKey((DHPublicKey) obj); 
                    dh.generateSharedSecret();
                }
                ois.close();
            }         
        }

    }
    
    public ByteArrayOutputStream writePublicKey() throws 
            IOException, InvalidKeyException, NoSuchAlgorithmException, 
            NoSuchProviderException, SignatureException {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            BufferedOutputStream bois = new BufferedOutputStream(bos);
            ObjectOutputStream oos = new ObjectOutputStream(bois);
            oos.writeObject(dh.getPublicKey());
            oos.flush();
            bos.close();
            signPublicKey(bos);
            return bos;
        }
        
        
    }
    
    /**
     *
     * @param message
     * @param iv
     * @return
     */
    @Override
    public byte[] encrypt(String message, IvParameterSpec iv) {
        return dh.encrypt(message, iv);
    }
    
    /**
     *
     * @param ciphertext
     * @param iv
     * @return
     */
    @Override
    public String decrypt(byte[] ciphertext, IvParameterSpec iv) {
        return dh.decrypt(ciphertext, iv);
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
    
    private void initSigning() throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "SUN");
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");

        keyGen.initialize(1024, random);

        KeyPair pair = keyGen.generateKeyPair();
        myPrivateKey = pair.getPrivate();
        myPublicKey = pair.getPublic();
        byte[] key = myPublicKey.getEncoded();
        try (FileOutputStream keyfos = new FileOutputStream(PUBLIC_KEY_FILE)) {
            keyfos.write(key);
        }
    }
    
    /**
     Signing the public key byte object output stream.
     * @param boas - the public key for DH exchange to be signed
     * @throws java.security.InvalidKeyException
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.security.NoSuchProviderException
     * @throws java.io.IOException
     * @throws java.security.SignatureException
     */
    public void signPublicKey(ByteArrayOutputStream boas) 
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, IOException, SignatureException {

        /* Create a Signature object and initialize it with the private key */

        Signature dsa = Signature.getInstance("SHA1withDSA", "SUN"); 

        dsa.initSign(myPrivateKey);
        
        try (BufferedInputStream bufin = new BufferedInputStream(
                new ByteArrayInputStream(boas.toByteArray()))) {
            byte[] buffer = new byte[1024];
            int len;
            while (bufin.available() != 0) {
                len = bufin.read(buffer);
                dsa.update(buffer, 0, len);
            }
        }
        
        /* Now that all the data to be signed has been read in, 
        generate a signature for it */

        byte[] realSig = dsa.sign();

         /* Save the signature in a file */ 
        try (FileOutputStream sigfos = new FileOutputStream(SIGNATURE_FILE)) {
            sigfos.write(realSig);
        }

    }
    
    /**
     * Verify the signature.
     * @param boas
     * @param signatureFile
     * @param publicKeyFile
     * @return true if the signature verifies else if not
     * @throws FileNotFoundException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws InvalidKeySpecException
     * @throws InvalidKeyException
     * @throws SignatureException 
     */
    public boolean verifyPublicKeySignature(ByteArrayOutputStream boas, 
            String signatureFile, String publicKeyFile) throws 
            FileNotFoundException, IOException, NoSuchAlgorithmException, 
            NoSuchProviderException, InvalidKeySpecException, InvalidKeyException, SignatureException {
            
        byte[] encKey;
        try (FileInputStream keyfis = new FileInputStream(publicKeyFile)) {
            encKey = new byte[keyfis.available()];
            keyfis.read(encKey);
        }

        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encKey);

        KeyFactory keyFactory = KeyFactory.getInstance("DSA", "SUN");
        PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);

        byte[] sigToVerify;
        try (FileInputStream sigfis = new FileInputStream(signatureFile)) {
            sigToVerify = new byte[sigfis.available()];
            sigfis.read(sigToVerify );
        }

        /* create a Signature object and initialize it with the public key */
        Signature sig = Signature.getInstance("SHA1withDSA", "SUN");
        sig.initVerify(pubKey);

        /* Update and verify the data */
        try (BufferedInputStream bufin = new BufferedInputStream(
                new ByteArrayInputStream(boas.toByteArray()))) {
            byte[] buffer = new byte[1024];
            int len;
            while (bufin.available() != 0) {
                len = bufin.read(buffer);
                sig.update(buffer, 0, len);
            }
        }


        boolean verifies = sig.verify(sigToVerify);
        return verifies;

    }
    
    /**
     * 
     * @param args 
     */
    public static void main(String[] args) {
        try {
            
            // każdy Client jest typem ChatClient, tworzymy więc obiekt tego typu
            // i inicjalizujemy jako ClientDH
            ChatClient karol = new ClientDH("Karol");
            
            // Pobieramy do Streama klucz publiczny klienta, ponieważ wiemy że 
            // aktualny obiekt jest właściwie obiektem ClientDH, więc możemy castować, 
            // żeby odwołać się do metod z klasy ClientDH (bo nie każdy ChatClient ma publiczne klucze etc.)
            ByteArrayOutputStream karolkey = ((ClientDH) karol).writePublicKey();
            
            // to samo inny klient
            ClientDH dominik = new ClientDH("Dominik");
            ByteArrayOutputStream dominikkey = dominik.writePublicKey();
            
            // Dominik otrzymuje publiczny klucz Karola - klucz jest obiektem ByteArrayOutPutStream, 
            // zaś dwie pozostałe argumenty to nazwa pliku zawierającego podpis cyfrowy oraz pliku
            // zawierającego klucz publiczny (ALE NIE TEN DO SZYFROWANIA KOMUNIKACJI, TYLKO DO PODPISU CYFROWEGO)
            // oba pliki powinny być wysłane np. korzystając z RemoteInputStream
            dominik.receivePublicKey(karolkey, ((ClientDH) karol).SIGNATURE_FILE, ((ClientDH)karol).PUBLIC_KEY_FILE);
            
            // to samo dla Karola
            ((ClientDH) karol).receivePublicKey(dominikkey, dominik.SIGNATURE_FILE, dominik.PUBLIC_KEY_FILE);
            
            // Karol chce wysłać wiadomość - to już są metody, które może wywołać każdy ChatClient
            String message = "Dominik, spałem cztery godziny.";
            // Karol generuje iv. (ponieważ enckrypcja jest w modzie CBC)
            IvParameterSpec iv = IvGenerator.generateIV(IvGenerator.AES_BLOCK_SIZE);
            // Karol enkryptuje
            byte[] encryption = karol.encrypt(message, iv);
            // Karol zapisuje zaenkryptowaną wiadomość do strumienia - teraz można ją wysłać na serwer.
            ByteArrayOutputStream baos = karol.writeMessage(encryption);
            // do odszyfrowania potrzebny jest ten sam iv, więc też zapisywany do strumienia 
            // i można go wysłać na serwer.
            ByteArrayOutputStream biv = karol.writeIv(iv);
            
            //// Powiedzmy, że serwer otrzymuje obie wiadomości i coś tam sobie robi.
            
            // Dominik otrzymuje wiadomość od serwera (otrzymuje obiekt ByteArrayOutputStream 
            // - powinien być input, ale już chuj.) oczywiście kazdy ChatClient może zrobić to, co Dominik teraz.
            byte[] received = dominik.receiveMessage(baos);
            
            // Dominik otrzymuje iv.
            IvParameterSpec iv2 = dominik.receiveIv(biv);
            
            // Dominik jako typ ChatClient może decryptować mając wiadomość i iv.
            String decryption = dominik.decrypt(received, iv2);
            
            // Dominik odczytuje wiadomość i wypisuje na ekranie.
            System.out.println(decryption);
            
            
        } catch (IOException | ClassNotFoundException | NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException | SignatureException  | InvalidKeySpecException ex) {
            Logger.getLogger(ClientDH.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        
        
    }

    
}
