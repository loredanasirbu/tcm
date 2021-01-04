package com.example.tcm.algorithm.aes;

import com.example.tcm.helper.TimestampHelper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.sql.Timestamp;

public class BCAlg {
    private static final int KEY_LENGTH = 32;
    private static final SecureRandom random = new SecureRandom();

    private static byte[] iv;

    private static Timestamp t1;
    private static Timestamp t2;
    private static final Logger logger = LoggerFactory.getLogger(BCAlg.class);


    private static SecretKey generateKey() {
        t1 = TimestampHelper.getTimestamp("Key Generation started: ");
        byte[] keyBytes = new byte[KEY_LENGTH];
        random.nextBytes(keyBytes);
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
        t2 = TimestampHelper.getTimestamp("Key Generation ended: ");
        TimestampHelper.displayTimeDistance("Key pair generation(BC) ", t1, t2);
        return keySpec;
    }

    private static byte[] encrypt(String plaintext, SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        t1 = TimestampHelper.getTimestamp("Encryption started: ");
        Security.addProvider(new BouncyCastleProvider());
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        String ivStr = "0123456789abcdef";
        iv = ivStr.getBytes(StandardCharsets.US_ASCII);
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] encrypted = cipher.doFinal(plaintext.getBytes());
        t2 = TimestampHelper.getTimestamp("Encryption ended: ");
        TimestampHelper.displayTimeDistance("Encryption AES(BC) ", t1, t2);
        return encrypted;
    }


    private static String decrypt(byte[] ciphertext, SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException {
        t1 = TimestampHelper.getTimestamp("Decryption started: ");
        Security.addProvider(new BouncyCastleProvider());
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] decrypted = cipher.doFinal(ciphertext);
        t2 = TimestampHelper.getTimestamp("Decryption ended: ");
        TimestampHelper.displayTimeDistance("Decryption AES(BC) ", t1, t2);
        return new String(decrypted);
    }

    public static void main(String[] args) throws Exception {

        SecretKey secretKey = generateKey();

        String plaintext = "Text";
        byte[] ciphertext = encrypt(plaintext, secretKey);
        String decryptedText = decrypt(ciphertext, secretKey);

        logger.info("Plain text was {} and decrypted text is: {}", plaintext, decryptedText);
    }
}
