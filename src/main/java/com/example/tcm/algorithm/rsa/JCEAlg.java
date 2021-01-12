package com.example.tcm.algorithm.rsa;

import com.example.tcm.helper.TimestampHelper;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;

public class JCEAlg extends RSA {

    public static KeyPair getKey() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        timer.start();
        keyPairGenerator.initialize(RSA_KEY_SIZE);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        logger.info("Key generation took {} ", timer.stop());
        return keyPair;
    }

    public static byte[] encrypt(String plainText, PublicKey publicKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        timer.start();
        byte[] cipherText = cipher.doFinal(plainText.getBytes());
        logger.info("Encrypt took {} ", timer.stop());
        return cipherText;
    }

    public static String decrypt(byte[] cipherTextArray, PrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        timer.start();
        byte[] decryptedTextArray = cipher.doFinal(cipherTextArray);
        logger.info("Decrypt took {} ", timer.stop());
        return new String(decryptedTextArray);
    }

    public static void main(String[] args) throws Exception {
        String plainMessage = "Before the modern era, cryptography focused on message confidentiality (i.e., encryption)—conversion of messages from a comprehensible form into an incomprehensible one and back again at the other end, rendering it unreadable by interceptors or eavesdroppers without secret knowledge (namely the key needed for decryption of that message). Encryption attempted to ensure secrecy in communications, such as those of spies, military leaders, and diplomats. ";
        KeyPair keys = getKey();
        byte[] encryptedMessage = encrypt(plainMessage, keys.getPublic());
        String decryptedMessage = decrypt(encryptedMessage, keys.getPrivate());
        TimestampHelper.displayJavaRuntimeMemoryUsage();
        logger.info("Before the modern era, cryptography focused on message confidentiality (i.e., encryption)—conversion of messages from a comprehensible form into an incomprehensible one and back again at the other end, rendering it unreadable by interceptors or eavesdroppers without secret knowledge (namely the key needed for decryption of that message). Encryption attempted to ensure secrecy in communications, such as those of spies, military leaders, and diplomats. In recent decades, the field has expanded beyond confidentiality concerns to include techniques for message integrity checking, sender/receiver identity authentication, digital signatures, interactive proofs and secure computation, among others. was:{} and decrypted message is: {}", plainMessage, decryptedMessage);
    }

}
