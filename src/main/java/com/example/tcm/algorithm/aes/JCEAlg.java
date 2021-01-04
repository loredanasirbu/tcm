package com.example.tcm.algorithm.aes;

import com.example.tcm.helper.TimestampHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.Timestamp;


public class JCEAlg {
    private static final String ENCRYPT_ALGO = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BIT = 128;
    private static final int IV_LENGTH_BYTE = 16;
    private static final int AES_KEY_BIT = 256;
    private static Timestamp t1;
    private static Timestamp t2;
    private static final Logger logger = LoggerFactory.getLogger(JCEAlg.class);

    public static byte[] getRandomNonce(int numBytes) {
        byte[] nonce = new byte[numBytes];
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }

    // AES secret key
    public static SecretKey getKey(int keysize) throws NoSuchAlgorithmException {
        t1 = TimestampHelper.getTimestamp("Key Generation started: ");
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(keysize, SecureRandom.getInstanceStrong());
        SecretKey secretKey = keyGen.generateKey();
        t2 = TimestampHelper.getTimestamp("Key Generation ended: ");
        TimestampHelper.displayTimeDistance("Key pair generation(JCE) ", t1, t2);
        return secretKey;
    }

    // AES-GCM needs GCMParameterSpec
    public static byte[] encrypt(byte[] pText, SecretKey secret, byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, secret, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
        byte[] encryptedText = cipher.doFinal(pText);
        return encryptedText;

    }

    // prefix IV length + IV bytes to cipher text
    public static byte[] encryptWithPrefixIV(byte[] pText, SecretKey secret, byte[] iv) throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        t1 = TimestampHelper.getTimestamp("Encryption with prefix IV started: ");
        byte[] cipherText = encrypt(pText, secret, iv);

        byte[] cipherTextWithIv = ByteBuffer.allocate(iv.length + cipherText.length)
                .put(iv)
                .put(cipherText)
                .array();
        t2 = TimestampHelper.getTimestamp("Encryption with IV ended: ");
        TimestampHelper.displayTimeDistance("Encryption AES(JCE) ", t1, t2);
        return cipherTextWithIv;

    }

    public static String decrypt(byte[] cText, SecretKey secret, byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);
        cipher.init(Cipher.DECRYPT_MODE, secret, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
        byte[] plainText = cipher.doFinal(cText);
        return new String(plainText, StandardCharsets.UTF_8);
    }

    public static String decryptWithPrefixIV(byte[] cText, SecretKey secret) throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        t1 = TimestampHelper.getTimestamp("Decryption started with prefix IV: ");
        ByteBuffer bb = ByteBuffer.wrap(cText);

        byte[] iv = new byte[IV_LENGTH_BYTE];
        bb.get(iv);
        byte[] cipherText = new byte[bb.remaining()];
        bb.get(cipherText);
        String plainText = decrypt(cipherText, secret, iv);
        t2 = TimestampHelper.getTimestamp("Decryption with prefix IV ended: ");
        TimestampHelper.displayTimeDistance("Decryption AES(JCE) ", t1, t2);
        return plainText;

    }

    public static void main(String[] args) throws Exception {

        String plaintext = "Text";

        // encrypt and decrypt need the same key.
        // get AES 256 bits (32 bytes) key
        SecretKey secretKey = getKey(AES_KEY_BIT);

        // encrypt and decrypt need the same IV.
        // AES-GCM needs IV 96-bit (12 bytes)
        byte[] iv = getRandomNonce(IV_LENGTH_BYTE);

        byte[] encryptedText = encryptWithPrefixIV(plaintext.getBytes(StandardCharsets.UTF_8), secretKey, iv);

        String decryptedText = decryptWithPrefixIV(encryptedText, secretKey);
        logger.info("Plain text was {} and decrypted text is: {}", plaintext, decryptedText);


    }

}
