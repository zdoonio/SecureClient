package com.clients;

import com.security.EnabledCiphers;
import com.security.IvGenerator;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

/**
 * Class just shows the way of using the 
 * ClientMPCreator and ClientMPSolver instances.
 * @author Karol
 */
public class ClientMPMain {
    
   public static void main(String[] args) {
       
       try {
           // Karol chce połączyć się z Dominikiem za pomocą MerklePuzzles, wybiera
           // że chce wysłać mu puzzle zakodowane za pomocą DES_CBC
           // (możliwe jeszcze DES_EDE_CBC lub AES_CBC, tutaj jednak czas
           // rozwiązywania puzzli jest ogromny - trzeba o tym wspomnieć w raporcie i helpie,
           // i generalnie przestrzec, że proces trwa w miarę długo.)
           ChatClient karol = new ClientMPCreator("Karol");
           // inicjalizacja Karola, chce on utworzyć 100000 puzzli zakodowanych DESem.
           ((ClientMPCreator) karol).init(2, EnabledCiphers.DES_CBC);
           
           // Karol tworzy plik z puzzlami (potem trzeba ten plik przesłać do klienta drugiego)
           ((ClientMPCreator) karol).createPuzzles("puzzle.puz");
           
           
           // Dominik musi być teraz MP Solverem - BuilderPattern ustawiamy wszystkie pola po kolei.
           ChatClient dominik = new ClientMPSolver("Dominik")
                   .setFragmentKeylen( ((ClientMPCreator) karol).getFragmentKeyLen() ) 
                   .setZerosKeylen( ((ClientMPCreator) karol).getZerosKeyLen() )
                   .setIv(((ClientMPCreator) karol).getPuzzleIv())
                   .setPuzzleAlgorithm(((ClientMPCreator) karol).getPuzzleAlgorithm())
                   .setSecretKeyAlgorithm(((ClientMPCreator) karol).getSecretKeyAlgorithm())
                   .setPuzzleFilename(((ClientMPCreator) karol).getPuzzlesFilename())
                   .setReplyFilename("reply.puz"); // plik w którym zapisywać będziemy odpowiedź
           
           // Dominik rozwiązuje puzzle i zapisuje je do pliku.
           // Plik trzeba wysłać teraz do Karola.
           ((ClientMPSolver) dominik).solvePuzzles();
           
           // Karol otrzymuje plik i zgadza się na klucz prywatny 
           // odpowiadający kluczowi publicznemu zawartemu w pliku.
           ((ClientMPCreator) karol).agreeOnKey("reply.puz");
           
           
           // teraz następuje enkrypcja i dekrypcja
           // metody używane przez ChatClienta
           // Karol chce napisać do Dominika
           String message = "Dominik, już naprawdę chce mi się spać.";
           
           IvParameterSpec iv = IvGenerator.generateIV(IvGenerator.AES_BLOCK_SIZE);
           
           // Karol enkryptuje wiadomość
           byte[] encryptedMessage = karol.encrypt(message, iv);
           
           ByteArrayOutputStream encryptedStream = karol.writeMessage(encryptedMessage);
           ByteArrayOutputStream writeIv = karol.writeIv(iv);
           
           // Dominik odbiera wiadomość oraz iv.
           byte[] received = dominik.receiveMessage(encryptedStream);
           IvParameterSpec iv2 = dominik.receiveIv(writeIv);
           
           // dekryptuje i odczytuje
           String plaintext = dominik.decrypt(received, iv2);
           
           System.out.println(plaintext);
           
           
       } catch (NoSuchAlgorithmException | FileNotFoundException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | UnsupportedEncodingException | InvalidAlgorithmParameterException ex) {
           Logger.getLogger(ClientMPMain.class.getName()).log(Level.SEVERE, null, ex);
       } catch (IOException ex) {
           Logger.getLogger(ClientMPMain.class.getName()).log(Level.SEVERE, null, ex);
       }
       
       
       
   } 
    
}
