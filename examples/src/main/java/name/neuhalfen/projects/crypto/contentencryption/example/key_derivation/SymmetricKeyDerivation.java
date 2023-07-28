package name.neuhalfen.projects.crypto.contentencryption.example.key_derivation;


import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

public class SymmetricKeyDerivation {


    /**
     * Derive a derived secret key from a masterkey and the record identifier of the .
     *
     * @param secretMasterkeyAsPassphrase  The masterkey in the form of a passphrase or other "text based" representation.
     * @param publicDerivedKeyId  An id unique to the record that should be encrypted with the created key. This could be a UUID, or the primary key of the database row.
     * @param nonce
     * @param keyLen
     * @return
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     */
    public SecretKey deriveKeyFromPassphraseAndRecordId(final char[] secretMasterkeyAsPassphrase, final char[] publicDerivedKeyId, byte[] nonce, int keyLen) throws InvalidKeySpecException, NoSuchAlgorithmException {
        // Make calculation "slow" so that an attacker has it more difficult.
        // Use workFactor >= 10000
        final int workFactor = 64000;

        // Also see here: https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet
        SecretKeyFactory kf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");

        // Derive from a password-masterkey
        // https://docs.oracle.com/javase/7/docs/api/javax/crypto/spec/PBEKeySpec.html

        char[] password = new char[secretMasterkeyAsPassphrase.length + publicDerivedKeyId.length];
        System.arraycopy(secretMasterkeyAsPassphrase, 0, password, 0, secretMasterkeyAsPassphrase.length);
        System.arraycopy(publicDerivedKeyId, 0, password, secretMasterkeyAsPassphrase.length, publicDerivedKeyId.length);

        KeySpec specs = new PBEKeySpec(password, nonce, workFactor, keyLen);
        SecretKey key = kf.generateSecret(specs);
        return new SecretKeySpec(key.getEncoded(), "AES");
    }

    public byte[] encrypt(char[] masterkey, char[] derivedKeyID) throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] salt = new byte[64];
        SecureRandom rnd = SecureRandom.getInstanceStrong();

        rnd.nextBytes(salt);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "SunJCE");
        SecretKey aesKey = deriveKey(masterkey, derivedKeyID, salt, 128);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey);
    }
}
