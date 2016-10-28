package de.deado.crypto;

import java.io.File;
import java.io.StringWriter;
import java.security.PrivateKey;
import java.security.SecureRandom;

import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.util.io.pem.PemObject;

import com.google.common.base.Charsets;
import com.google.common.io.Files;

public class EncryptedPrivateKeyWriter {

    public void encrypt(PrivateKey privateKey, String password, String filenameWithoutExtension) throws Exception {
        
        JceOpenSSLPKCS8EncryptorBuilder encryptorBuilder = new JceOpenSSLPKCS8EncryptorBuilder(PKCS8Generator.PBE_SHA1_RC2_128);  
        encryptorBuilder.setRandom(new SecureRandom());  
        encryptorBuilder.setPasssword(password.toCharArray());
        OutputEncryptor encryptor = encryptorBuilder.build();  
      
        JcaPKCS8Generator pkcs8Generator = new JcaPKCS8Generator(privateKey, encryptor);  
        PemObject pemObject = pkcs8Generator.generate();  
        StringWriter stringWriter = new StringWriter();  
        try (JcaPEMWriter pw = new JcaPEMWriter(stringWriter)) {  
          pw.writeObject(pemObject);  
        }  
        String pkcs8KeyString = stringWriter.toString();  
        Files.write(pkcs8KeyString, new File(filenameWithoutExtension + ".pkcs8"), Charsets.US_ASCII);  
    }
}
