package com.clients;

import com.security.IvGenerator;
import com.security.KeyAgreementEntity;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.spec.IvParameterSpec;

/**
 *
 * @author Karol
 */
public class ClientPD implements ChatClient {

    public final String name;
    
    public final static int ALICE = 0;
    
    public final static int BOB = 1;
    
    private final WriteReceiveClient wrc; 
    
    private final KeyAgreementEntity kae;
    
    public ClientPD(String name) {
        this.name = name;
        kae = new KeyAgreementEntity();
        wrc = new WriteReceiveClientImpl();
    }
    
    public void init(int BobOrAlice, String password) throws 
            NoSuchAlgorithmException, InvalidKeySpecException, Exception {
        switch (BobOrAlice) {
            case ALICE:
                kae.generatePredistributedKey(password);
                kae.generateSessionKey();
                
                break;
            case BOB:
                kae.generatePredistributedKey(password);
                break;
            default:
                throw new Exception();
        }
    }
    
    public void receiveSessionKey(ByteArrayOutputStream boas) {
        byte[] key = boas.toByteArray();
        kae.decryptSessionKey(key);
        
    }
    
    public ByteArrayOutputStream encryptSessionKey() throws IOException {
        ByteArrayOutputStream boas = new ByteArrayOutputStream();
        byte[] key = kae.encryptSessionKey();
        boas.write(key, 0, key.length);
        boas.close();
        return boas;
    }

    @Override
    public byte[] encrypt(String message, IvParameterSpec iv) {
        return kae.encrypt(message, iv);
    }

    @Override
    public String decrypt(byte[] message, IvParameterSpec iv) {
        return kae.decrypt(message, iv);
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
    
    
    
    public static void main(String[] args) throws InvalidKeySpecException, Exception {
        
        // W tym podejściu klient Alicja i klient Bob wcześniej się spotkali i umówili się,
        // że będą mieli wspólne hasło
        String password = "gowno"; // bez polskich znaków należy pamiętać o tym
        
        // Tworzymy klientów, trzeba pamiętać, że nie może być dwóhc Alice, albo dwóch Bobów na raz.
        // Zawsze jeden klient to Alice drugi to Bob. (chodzi o flagi ClientPD.Alice, ClientPD.Bob)
        // robimy init ich z tym ich hasłem i flagą, kto jest kto.
        ChatClient Alice = new ClientPD("Alice");
        ((ClientPD) Alice).init(ClientPD.ALICE, password); // tu jest flaaga Alice
        
        ChatClient Bob = new ClientPD("Bob");
        ((ClientPD) Bob).init(ClientPD.BOB, password); // tu jest flaga Bob
        
        // Alicja zawsze (z powodu flagi) 
        // generuje klucz sesji, więc to dla niej należy wywołać metodę encryptSessionKey()
        ByteArrayOutputStream key = ((ClientPD) Alice).encryptSessionKey();
        
        // Bob otrzymuje zaszyfrowany klucz sesji. jak go otrzymuje, to sam od razu do deckryptuje 
        // i w ten sposób umówili się na wspólny klucz sesji.
        ((ClientPD) Bob).receiveSessionKey(key);
        
        // I poniżej używamy metod ChatClienta
        
        // Alicja chce teraz wysłać wiadomość.
        String message = "Bob, słyszysz mnie?";
        // Alicja generuje iv.
        IvParameterSpec iv = IvGenerator.generateIV(IvGenerator.AES_BLOCK_SIZE);  // do enkrypcji symetrycznej używamy AES128 i dlatego zawsze AES_BLOCK_SIZE
        // Alicja enkryptuje wiadomosc.
        byte[] encryption = Alice.encrypt(message, iv);
        // Alicja wpakowuje w strumień wiadomość oraz iv
        ByteArrayOutputStream boas = Alice.writeMessage(encryption);
        ByteArrayOutputStream ivboas = Alice.writeIv(iv);
        
        // Bob otrzymuje strumień z wiadomością i strumień z iv.
        byte[] received = Bob.receiveMessage(boas);
        IvParameterSpec iv2 = Bob.receiveIv(ivboas);
        
        // Bob dekryptuje
        String decryption = Bob.decrypt(received, iv2);
        
        // Bob wyświetla wiadomość.
        System.out.println(decryption);
        
    }


}
