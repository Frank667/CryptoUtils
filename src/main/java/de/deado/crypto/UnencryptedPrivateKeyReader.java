package de.deado.crypto;

import java.io.File;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

import org.bouncycastle.util.encoders.Base64;

import com.google.common.base.Charsets;
import com.google.common.io.Files;

public class UnencryptedPrivateKeyReader {

    public PrivateKey readFromPkcs8(String filename) throws Exception {
        String unencrypted = Files.toString(new File(filename + ".pkcs8"), Charsets.US_ASCII);
        unencrypted = unencrypted.replace("-----BEGIN PRIVATE KEY-----", ""); 
        unencrypted = unencrypted.replace("-----END PRIVATE KEY-----", "");  
        byte[] encoded = Base64.decode(unencrypted);  
        PKCS8EncodedKeySpec kspec = new PKCS8EncodedKeySpec(encoded);  
        KeyFactory kf = KeyFactory.getInstance("RSA");  
        return kf.generatePrivate(kspec);  
    }
}
