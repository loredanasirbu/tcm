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
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(keysize, SecureRandom.getInstanceStrong());
        timer.start();
        SecretKey key = keyGen.generateKey();
        logger.info("Key generation took {} ", timer.stop());
        return key;
    }

    public static byte[] encrypt(byte[] pText, SecretKey secret, byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, secret, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
        timer.start();
        byte[] encryptedText = cipher.doFinal(pText);
        logger.info("Encrypt took {} ", timer.stop());
        return encryptedText;
    }

    public static String decrypt(byte[] cText, SecretKey secret, byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);
        cipher.init(Cipher.DECRYPT_MODE, secret, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
        timer.start();
        byte[] plainText = cipher.doFinal(cText);
        logger.info("Decrypt took {} ", timer.stop());

        return new String(plainText, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) throws Exception {
        String plainMessage = "Before the modern era, cryptography focused on message confidentiality (i.e., encryption)—conversion of messages from a comprehensible form into an incomprehensible one and back again at the other end, rendering it unreadable by interceptors or eavesdroppers without secret knowledge (namely the key needed for decryption of that message). Encryption attempted to ensure secrecy in communications, such as those of spies, military leaders, and diplomats. ";
        SecretKey key = generateKey(AES_KEY_SIZE);
        byte[] iv = getRandomNonce(IV_LENGTH_BYTE);
        byte[] encryptedMessage = encrypt(plainMessage.getBytes(StandardCharsets.UTF_8), key, iv);
        String decryptedMessage = decrypt(encryptedMessage, key, iv);
        TimestampHelper.displayJavaRuntimeMemoryUsage();
        logger.info("Before the modern era, cryptography focused on message confidentiality (i.e., encryption)—conversion of messages from a comprehensible form into an incomprehensible one and back again at the other end, rendering it unreadable by interceptors or eavesdroppers without secret knowledge (namely the key needed for decryption of that message). Encryption attempted to ensure secrecy in communications, such as those of spies, military leaders, and diplomats. In recent decades, the field has expanded beyond confidentiality concerns to include techniques for message integrity checking, sender/receiver identity authentication, digital signatures, interactive proofs and secure computation, among others. was: {} and decrypted message is: {}", plainMessage, decryptedMessage);
    }
}
