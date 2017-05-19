package name.neuhalfen.projects.crypto.contentencryption.example;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;


public class Main {
    static void installBCProvider() {
        try {
            if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
                Security.addProvider(new BouncyCastleProvider());
            }
        } catch (SecurityException e) {
            System.err.println("Failed to install BouncyCastle provider");
            throw e;
         }
    }


    public static void main(String[] args) {
        installBCProvider();
    }
}
