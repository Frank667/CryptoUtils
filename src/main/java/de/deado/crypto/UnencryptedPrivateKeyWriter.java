package de.deado.crypto;

import java.io.File;
import java.io.StringWriter;
import java.security.PrivateKey;

import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.util.io.pem.PemObject;

import com.google.common.base.Charsets;
import com.google.common.io.Files;

public class UnencryptedPrivateKeyWriter {
    
    
    public void encrypt(PrivateKey privateKey, String filenameWithoutExtension) throws Exception {
        JcaPKCS8Generator pkcs8Generator = new JcaPKCS8Generator(privateKey, null);  
        PemObject pemObject = pkcs8Generator.generate();  
        StringWriter stringWriter = new StringWriter();  
        try (JcaPEMWriter pw = new JcaPEMWriter(stringWriter)) {  
          pw.writeObject(pemObject);  
        }  
        String pkcs8KeyString = stringWriter.toString(); 
        Files.write(pkcs8KeyString, new File(filenameWithoutExtension + ".pkcs8"), Charsets.US_ASCII);  
    }

}
