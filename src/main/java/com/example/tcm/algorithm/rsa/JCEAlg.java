package com.example.tcm.algorithm.rsa;

import com.example.tcm.helper.Helper;
import com.example.tcm.helper.TimestampHelper;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;

public class JCEAlg extends RSA {

    public static KeyPair getKey() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(RSA_KEY_SIZE);
        t1 = TimestampHelper.getTimestamp("Key Pair Generation started: ");
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        t2 = TimestampHelper.getTimestamp("Key Pair Generation ended: ");
        TimestampHelper.displayTimeDistance("Key pair generation(JCE) ", t1, t2);

        return keyPair;
    }

    public static byte[] encrypt(String plainText, PublicKey publicKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        t1 = TimestampHelper.getTimestamp("Encryption started: ");
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] cipherText = cipher.doFinal(plainText.getBytes());
        t2 = TimestampHelper.getTimestamp("Encryption ended: ");
        TimestampHelper.displayTimeDistance("Encryption RSA(JCE) ", t1, t2);

        return cipherText;
    }

    public static String decrypt(byte[] cipherTextArray, PrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        t1 = TimestampHelper.getTimestamp("Decryption started: ");
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedTextArray = cipher.doFinal(cipherTextArray);
        t2 = TimestampHelper.getTimestamp("Decryption ended: ");
        TimestampHelper.displayTimeDistance("Decryption RSA(JCE) ", t1, t2);

        return new String(decryptedTextArray);
    }

    public static void main(String[] args) throws Exception {
        String plainMessage = "Plain message";
        KeyPair keys = getKey();
        byte[] encryptedMessage = encrypt(plainMessage, keys.getPublic());
        logger.info(Helper.getHexString(encryptedMessage));
        String decryptedMessage = decrypt(encryptedMessage, keys.getPrivate());
        TimestampHelper.displayJavaRuntimeMemoryUsage();
        logger.info("Plain message was:{} and decrypted message is: {}", plainMessage, decryptedMessage);
    }

}
