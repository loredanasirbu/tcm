package com.example.tcm.algorithm.aes;

import com.example.tcm.helper.TimestampHelper;
import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.Security;

public class BCAlg extends AES {

    public static byte[] generateKey(int keysize) {
        CipherKeyGenerator keyGen = new CipherKeyGenerator();
        timer.start();
        keyGen.init(new KeyGenerationParameters(new SecureRandom(), keysize)); //key is 256 bits
        byte[] key = keyGen.generateKey();
        logger.info("Key generation took {} ", timer.stop());
        return key;
    }

    public static byte[] encrypt(byte[] plain, CipherParameters ivAndKey) throws Exception {
        GCMBlockCipher aes = new GCMBlockCipher(new AESEngine());
        aes.init(true, ivAndKey);
        timer.start();
        byte[] cipherMessage = cipherMessage(aes, plain);
        logger.info("Encrypt took {} ", timer.stop());

        return cipherMessage;
    }

    public static String decrypt(byte[] cipher, CipherParameters ivAndKey) throws Exception {
        GCMBlockCipher aes = new GCMBlockCipher(new AESEngine());
        aes.init(false, ivAndKey);
        timer.start();
        byte[] message = cipherMessage(aes, cipher);
        logger.info("Decrypt took {} ", timer.stop());
        return new String(message, StandardCharsets.UTF_8);
    }

    public static byte[] cipherMessage(GCMBlockCipher cipher, byte[] data) throws Exception {
        byte[] outputBuffer = new byte[cipher.getOutputSize(data.length)];

        int l1 = cipher.processBytes(data, 0, data.length, outputBuffer, 0);
        int l2 = cipher.doFinal(outputBuffer, l1);

        byte[] result = new byte[l1 + l2];
        System.arraycopy(outputBuffer, 0, result, 0, result.length);

        return result;
    }


    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        String plainMessage = "Before the modern era, cryptography focused on message confidentiality (i.e., encryption)—conversion of messages from a comprehensible form into an incomprehensible one and back again at the other end, rendering it unreadable by interceptors or eavesdroppers without secret knowledge (namely the key needed for decryption of that message). Encryption attempted to ensure secrecy in communications, such as those of spies, military leaders, and diplomats. ";
        byte[] key = generateKey(AES_KEY_SIZE);
        byte[] iv = getRandomNonce(IV_LENGTH_BYTE);
        CipherParameters ivAndKey = new ParametersWithIV(new KeyParameter(key), iv);
        byte[] encryptedMessage = encrypt(plainMessage.getBytes(StandardCharsets.UTF_8), ivAndKey);
        String decryptedMessage = decrypt(encryptedMessage, ivAndKey);
        TimestampHelper.displayJavaRuntimeMemoryUsage();
        logger.info("Plain text was {} and decrypted text is: {}", plainMessage, decryptedMessage);
    }
}
