package com.clients;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.spec.IvParameterSpec;

/**
 * Implementacja write, receive etc. Każdy ChatClient będzie korzystał z tego obiektu 
 * i praktycznie w taki sam sposób zapisywał, odczytywał i inne pierdoły.
 * Umieściłem wszystko w tej jednej klasie, bo po pierwsze to co wyżej - każdy podobnie robi,
 * a po drugie łatwiej będzie zmienić zwracane typy, np. jeśli potrzeba będzie zamiast ByteArratOuputStream, 
 * jakiś inny Stream, to mniej pieprzenia się z poprawianiem wszędzie kodu.
 * @author Karol
 */
public class WriteReceiveClientImpl implements WriteReceiveClient {
    
    @Override
    public ByteArrayOutputStream writeMessage(byte[] encryptedMessage) {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            baos.write(encryptedMessage, 0, encryptedMessage.length);
            baos.close();
            return baos;
        } catch (IOException ex) {
            Logger.getLogger(ClientDH.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    @Override
    public byte[] receiveMessage(ByteArrayOutputStream encryptedMessage) {
        return encryptedMessage.toByteArray();
    }
    
    
    @Override
    public ByteArrayOutputStream writeIv(IvParameterSpec iv) {
        try {
            byte[] ivb = iv.getIV();
            ByteArrayOutputStream boas = new ByteArrayOutputStream();
            boas.write(ivb);
            boas.flush();
            boas.close();
            return boas;
        } catch (IOException ex) {
            Logger.getLogger(ClientDH.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    @Override
    public IvParameterSpec receiveIv(ByteArrayOutputStream iv) {
        
        byte[] b = iv.toByteArray();
        byte[] bytes;
        try (ByteArrayInputStream bais = new ByteArrayInputStream(b)) {
            int len = b.length;
            bytes = new byte[len];
            bais.read(bytes);
            return new IvParameterSpec(bytes);
        } catch (IOException ex) {
            Logger.getLogger(ClientDH.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
        
    }
    
}
