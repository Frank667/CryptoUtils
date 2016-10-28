package de.deado.crypto;

import java.io.File;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.bouncycastle.util.encoders.Base64;

import com.google.common.base.Charsets;
import com.google.common.io.Files;

public class EncryptedPrivateKeyReader {
    public PrivateKey readFromPkcs8(String password, String filename) throws Exception {
        String encrypted = Files.toString(new File(filename + ".pkcs8"), Charsets.UTF_8);        
        encrypted = encrypted.replace("-----BEGIN ENCRYPTED PRIVATE KEY-----", "");  
        encrypted = encrypted.replace("-----END ENCRYPTED PRIVATE KEY-----", "");  
        byte[] base64DecodedBytes = Base64.decode(encrypted.getBytes(Charsets.US_ASCII));
        EncryptedPrivateKeyInfo pkInfo = new EncryptedPrivateKeyInfo(base64DecodedBytes);  
        PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray()); 
        SecretKeyFactory pbeKeyFactory = SecretKeyFactory.getInstance(pkInfo.getAlgName());  
        PKCS8EncodedKeySpec encodedKeySpec = pkInfo.getKeySpec(pbeKeyFactory.generateSecret(keySpec));  
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");  
        return keyFactory.generatePrivate(encodedKeySpec);  
      
    }
}
