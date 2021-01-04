package com.example.tcm.algorithm.rsa;

import com.example.tcm.helper.Helper;
import com.example.tcm.helper.TimestampHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.sql.Timestamp;

public class JCEAlg {
    private static Timestamp t1;
    private static Timestamp t2;
    private static final Logger logger = LoggerFactory.getLogger(JCEAlg.class);

    // Get RSA keys. Uses key size of 4096.
    public static KeyPair getKey() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(4096);
        t1 = TimestampHelper.getTimestamp("Key Pair Generation started: ");
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        t2 = TimestampHelper.getTimestamp("Key Pair Generation ended: ");
        TimestampHelper.displayTimeDistance("Key pair generation(JCE) ", t1, t2);

        return keyPair;
    }

    public static byte[] encrypt(String plainText, PublicKey publicKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        t1 = TimestampHelper.getTimestamp("Encryption started: ");
        Cipher cipher = Cipher.getInstance("RSA");
        //Initialize Cipher for ENCRYPT_MODE
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        //Perform Encryption and compute the execution time
        byte[] cipherText = cipher.doFinal(plainText.getBytes());
        t2 = TimestampHelper.getTimestamp("Encryption ended: ");
        TimestampHelper.displayTimeDistance("Encryption RSA(JCE) ", t1, t2);
        return cipherText;
    }

    public static String decrypt(byte[] cipherTextArray, PrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        t1 = TimestampHelper.getTimestamp("Decryption started: ");
        Cipher cipher = Cipher.getInstance("RSA");
        //Initialize Cipher for DECRYPT_MODE
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        //Perform Decryption and compute the execution time
        byte[] decryptedTextArray = cipher.doFinal(cipherTextArray);
        t2 = TimestampHelper.getTimestamp("Decryption ended: ");
        TimestampHelper.displayTimeDistance("Decryption RSA(JCE) ", t1, t2);
        return new String(decryptedTextArray);
    }

    public static void main(String[] args) throws Exception {
        String plainMessage = "Text";
        KeyPair keys = getKey();
        byte[] textArray = JCEAlg.encrypt(plainMessage, keys.getPublic());
        logger.info(Helper.getHexString(textArray));
        String decryptedMessage = JCEAlg.decrypt(textArray, keys.getPrivate());
        TimestampHelper.displayJavaRuntimeMemoryUsage();
        logger.info("Plain text was:{} and decrypted text is: {}", plainMessage, decryptedMessage);
    }

}
