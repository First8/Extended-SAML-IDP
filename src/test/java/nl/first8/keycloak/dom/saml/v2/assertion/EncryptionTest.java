package nl.first8.keycloak.dom.saml.v2.assertion;

import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

public class EncryptionTest {


    private static String algorithm = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

    @Test
    void testEncryption() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        System.out.println("RSA 2048 encryption OAEP SHA-256 string");

        String dataToEncryptString = "The quick brown fox jumps over the lazy dog";
        byte[] dataToEncrypt = dataToEncryptString.getBytes(StandardCharsets.UTF_8);
        System.out.println("plaintext: " + dataToEncryptString);

        // encryption
        System.out.println("\n* * * encrypt the plaintext with the RSA public key * * *");
        PublicKey publicKeyLoad = loadRsaPublicKeyPem();
        String ciphertextBase64 = base64Encoding(rsaEncryptionOaepSha256(publicKeyLoad, dataToEncrypt));
        System.out.println("ciphertextBase64: " + ciphertextBase64);

        // transport the encrypted data to recipient

        // receiving the encrypted data, decryption
        System.out.println("\n* * * decrypt the ciphertext with the RSA private key * * *");
        String ciphertextReceivedBase64 = ciphertextBase64;
        System.out.println("ciphertextReceivedBase64: " + ciphertextReceivedBase64);
        PrivateKey privateKeyLoad = loadRsaPrivateKeyPem();
        byte[] ciphertextReceived = base64Decoding(ciphertextReceivedBase64);
        byte[] decryptedtextByte = rsaDecryptionOaepSha256(privateKeyLoad, ciphertextReceived);
        System.out.println("decryptedtext: " + new String(decryptedtextByte, StandardCharsets.UTF_8));
    }

    public static byte[] rsaEncryptionOaepSha256 (PublicKey publicKey, byte[] plaintextByte) throws NoSuchAlgorithmException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidAlgorithmParameterException {
        byte[] ciphertextByte = null;
        Cipher encryptCipher = Cipher.getInstance(algorithm);
        OAEPParameterSpec oaepParameterSpecJCE = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey, oaepParameterSpecJCE);
        ciphertextByte = encryptCipher.doFinal(plaintextByte);
        return ciphertextByte;
    }

    public static byte[] rsaDecryptionOaepSha256 (PrivateKey privateKey, byte[] ciphertextByte) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        byte[] decryptedtextByte = null;
        Cipher decryptCipher = Cipher.getInstance(algorithm);
        OAEPParameterSpec oaepParameterSpecJCE = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
        decryptCipher.init(Cipher.DECRYPT_MODE, privateKey, oaepParameterSpecJCE);
        decryptedtextByte = decryptCipher.doFinal(ciphertextByte);
        return decryptedtextByte;
    }

    private static String base64Encoding(byte[] input) {
        return Base64.getEncoder().encodeToString(input);
    }
    private static byte[] base64Decoding(String input) {
        return Base64.getDecoder().decode(input);
    }

    private static PrivateKey loadRsaPrivateKeyPem() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        byte[] privateKeyBytes = getFileFromResource("keys/private.key");
        EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        return keyFactory.generatePrivate(privateKeySpec);
    }

    private static PublicKey loadRsaPublicKeyPem() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        byte[] publicKeyBytes = getFileFromResource("keys/public.key");
        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        return keyFactory.generatePublic(publicKeySpec);
    }

    private static byte[] getFileFromResource(String fileName) throws IOException {
        ClassLoader classLoader = EncryptionTest.class.getClassLoader();
        try (InputStream inputStream = classLoader.getResourceAsStream(fileName)) {

            if (inputStream == null) {
                throw new IllegalArgumentException("file not found! " + fileName);
            } else {
                return inputStream.readAllBytes();
            }
        }
    }
}
