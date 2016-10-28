package de.deado.crypto;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;

public class ProofOfConcept {
    
    private static final String UNENCRYPTED_PRIVATE_FILENAME = "unencrypted_private";
    private static final String ENCRYPTED_PRIVATE_FILENAME = "encrypted_private";
    private static final String PASSWORD = "5up3r53cr3t";

    public static void main(String[] args) throws Exception {
        UnencryptedPrivateKeyWriter keyWriter = new UnencryptedPrivateKeyWriter();
        PrivateKey privateKey = createKeyPair().getPrivate();
        keyWriter.encrypt(privateKey, UNENCRYPTED_PRIVATE_FILENAME);
        
        EncryptedPrivateKeyWriter encryptedWriter = new EncryptedPrivateKeyWriter();
        encryptedWriter.encrypt(privateKey, PASSWORD, ENCRYPTED_PRIVATE_FILENAME);
        
        UnencryptedPrivateKeyReader unencryptedKeyReader = new UnencryptedPrivateKeyReader();
        PrivateKey unencryptedKey = unencryptedKeyReader.readFromPkcs8(UNENCRYPTED_PRIVATE_FILENAME);
        
        EncryptedPrivateKeyReader encryptedKeyReader = new EncryptedPrivateKeyReader();
        PrivateKey encryptedKey = encryptedKeyReader.readFromPkcs8(PASSWORD, ENCRYPTED_PRIVATE_FILENAME);
        
        System.out.println("Schlüssel sind gleich: " + unencryptedKey.equals(encryptedKey));
    }

    
    public static KeyPair createKeyPair() throws Exception {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");  
        kpGen.initialize(2048, new SecureRandom());  
        return kpGen.generateKeyPair();  
    }
}
