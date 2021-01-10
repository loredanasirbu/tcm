package com.example.tcm.algorithm.aes;

import com.example.tcm.helper.TimestampHelper;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class JCEAlg extends AES {

    public static SecretKey generateKey(int keysize) throws NoSuchAlgorithmException {
        t1 = TimestampHelper.getTimestamp("Key Generation started: ");
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(keysize, SecureRandom.getInstanceStrong());
        SecretKey key = keyGen.generateKey();
        t2 = TimestampHelper.getTimestamp("Key Generation ended: ");
        TimestampHelper.displayTimeDistance("Key pair generation(JCE) ", t1, t2);

        return key;
    }

    public static byte[] encrypt(byte[] pText, SecretKey secret, byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException {
        t1 = TimestampHelper.getTimestamp("Encryption with prefix IV started: ");
        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, secret, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
        byte[] encryptedText = cipher.doFinal(pText);
        t2 = TimestampHelper.getTimestamp("Encryption with IV ended: ");
        TimestampHelper.displayTimeDistance("Encryption AES(JCE) ", t1, t2);

        return encryptedText;
    }

    public static String decrypt(byte[] cText, SecretKey secret, byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        t1 = TimestampHelper.getTimestamp("Decryption started: ");
        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);
        cipher.init(Cipher.DECRYPT_MODE, secret, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
        byte[] plainText = cipher.doFinal(cText);
        t2 = TimestampHelper.getTimestamp("Decryption ended: ");
        TimestampHelper.displayTimeDistance("Decryption AES(JCE) ", t1, t2);

        return new String(plainText, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) throws Exception {
        String plainMessage = "Plain message";
        SecretKey key = generateKey(AES_KEY_SIZE);
        byte[] iv = getRandomNonce(IV_LENGTH_BYTE);
        byte[] encryptedMessage = encrypt(plainMessage.getBytes(StandardCharsets.UTF_8), key, iv);
        String decryptedMessage = decrypt(encryptedMessage, key,iv);
        TimestampHelper.displayJavaRuntimeMemoryUsage();
        logger.info("Plain message was: {} and decrypted message is: {}", plainMessage, decryptedMessage);
    }
}
