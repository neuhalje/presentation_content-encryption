package name.neuhalfen.projects.crypto.contentencryption.example.pgp_public_key_encryption;


import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BouncyGPG;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.InMemoryKeyring;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfigs;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.util.io.Streams;

import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;

import static name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeyringConfigCallbacks.withPassword;

public class Sender {
    private final static String VERY_SECRET_MESSAGE = "I don't like broccoli";

    public byte[] sendMessage() throws IOException, PGPException, NoSuchAlgorithmException, SignatureException, NoSuchProviderException {
        final KeyringConfig keyRing = sendersKeyRing();
        final ByteArrayOutputStream encryptedAndSignedStream = new ByteArrayOutputStream();

        try (

                // Wrap encryptedAndSignedStream with encryption and signing.
                //
                // encryptionStream is now a stream that encrypts & signs everything written
                // to it, and writes the encrypted data to encryptedAndSignedStream.
                final OutputStream encryptionStream = BouncyGPG
                        .encryptToStream()
                        .withConfig(keyRing)
                        .withStrongAlgorithms()
                        .toRecipient("recipient@example.com")
                        .andSignWith("sender.signonly@example.com")
                        .armorAsciiOutput()
                        .andWriteTo(encryptedAndSignedStream);

                final InputStream plainText = new ByteArrayInputStream(VERY_SECRET_MESSAGE.getBytes())
        ) {
            Streams.pipeAll(plainText, encryptionStream);
        }
        return encryptedAndSignedStream.toByteArray();

    }



    /**
     * @return Return the keyring used by the SENDER of the message
     */
    KeyringConfig sendersKeyRing() throws IOException, PGPException {
        // To decrypt our (SENDER_PRIVATE_KEY) private key, we need a password.
        // Our key has been protected with the password "sign".
        final InMemoryKeyring sendersKeyring = KeyringConfigs.forGpgExportedKeys(withPassword("sign"));

        // We ENCRYPT TO the recipients public key
        sendersKeyring.addPublicKey(KeyRings.RECIPIENT_PUBLIC_KEY.getBytes());

        // the message will be signed BY the senders private key
        sendersKeyring.addSecretKey(KeyRings.SENDER_PRIVATE_KEY.getBytes());

        return sendersKeyring;
    }
}
