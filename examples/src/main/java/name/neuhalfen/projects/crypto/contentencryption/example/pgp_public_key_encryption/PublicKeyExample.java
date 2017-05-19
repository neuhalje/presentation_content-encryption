package name.neuhalfen.projects.crypto.contentencryption.example.pgp_public_key_encryption;


import name.neuhalfen.projects.crypto.contentencryption.example.Main;
import org.bouncycastle.openpgp.PGPException;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;

public class PublicKeyExample {
    public static void main(String[] args) throws PGPException, IOException, NoSuchProviderException, SignatureException, NoSuchAlgorithmException {
        Main.installBCProvider();

        // The sender encrypts & signs a message.
        Sender sender = new Sender();
        final byte[] message = sender.sendMessage();

        // The recipient decrypts the message.
        Recipient recipient = new Recipient();
        recipient.readMessage(message);
    }
}
