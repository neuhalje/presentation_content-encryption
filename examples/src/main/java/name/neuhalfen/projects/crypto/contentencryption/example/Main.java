package name.neuhalfen.projects.crypto.contentencryption.example;

import name.neuhalfen.projects.crypto.contentencryption.example.pgp_public_key_encryption.PublicKeyExample;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;


public class Main {
    public static void installBCProvider() {
        try {
            if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
                Security.addProvider(new BouncyCastleProvider());
            }
        } catch (SecurityException e) {
            System.err.println("Failed to install BouncyCastle provider");
            throw e;
         }
    }


    public static void main(String[] args) throws NoSuchAlgorithmException, PGPException, SignatureException, NoSuchProviderException, IOException {
        installBCProvider();

        PublicKeyExample.main(args);
    }
}
