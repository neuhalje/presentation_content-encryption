package name.neuhalfen.projects.crypto.contentencryption.example.pgp_public_key_encryption;


import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BouncyGPG;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.InMemoryKeyring;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfigs;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.util.io.Streams;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchProviderException;

import static name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeyringConfigCallbacks.withPassword;

public class Recipient {

    // TODO: Add support for invalid/failing signature check


    public void readMessage(byte[] encryptedMessage) throws IOException, PGPException, NoSuchProviderException {
        final KeyringConfig keyRing = recipientsKeyRing();

        byte[] decrypted;

        try (
                final InputStream encryptedAndSignedStream = new ByteArrayInputStream(encryptedMessage);

                // Wrap encryptedAndSignedStream with decryption and signature verification.
                //
                // plainText is now a stream that decrypts everything read
                // from it by reading the ciphertext from encryptedAndSignedStream.
                final InputStream plainText = BouncyGPG
                        .decryptAndVerifyStream()
                        .withConfig(keyRing)
                        .andRequireSignatureFromAllKeys("sender.signonly@example.com")
                        .fromEncryptedInputStream(encryptedAndSignedStream)
        ) {
            decrypted = Streams.readAll(plainText);
        }

        System.out.println("The sender send me: " + new String(decrypted));
    }

    /**
     * @return Return the keyring used by the RECIPIENT of the message
     */
    KeyringConfig recipientsKeyRing() throws IOException, PGPException {
        final InMemoryKeyring sendersKeyring = KeyringConfigs.forGpgExportedKeys(withPassword("recipient"));

        // We need the senders public key to VERIFY the signature
        sendersKeyring.addPublicKey(KeyRings.SENDER_PUBLIC_KEY.getBytes());

        // We need the recipients private key to DECRYPT
        sendersKeyring.addSecretKey(KeyRings.RECIPIENT_PRIVATE_KEY.getBytes());

        return sendersKeyring;
    }

}
