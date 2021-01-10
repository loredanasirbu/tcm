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
        t1 = TimestampHelper.getTimestamp("Key Generation started: ");
        CipherKeyGenerator keyGen = new CipherKeyGenerator();
        keyGen.init(new KeyGenerationParameters(new SecureRandom(), keysize)); //key is 256 bits
        byte[] key = keyGen.generateKey();
        t2 = TimestampHelper.getTimestamp("Key Generation ended: ");
        TimestampHelper.displayTimeDistance("Key pair generation(BC) ", t1, t2);

        return key;
    }

    public static byte[] encrypt(byte[] plain, CipherParameters ivAndKey) throws Exception {
        t1 = TimestampHelper.getTimestamp("Encryption started: ");
        GCMBlockCipher aes = new GCMBlockCipher(new AESEngine());
        aes.init(true, ivAndKey);
        byte[] cipherMessage = cipherMessage(aes, plain);
        t2 = TimestampHelper.getTimestamp("Encryption ended: ");
        TimestampHelper.displayTimeDistance("Encryption AES(BC) ", t1, t2);

        return cipherMessage;
    }

    public static String decrypt(byte[] cipher, CipherParameters ivAndKey) throws Exception {
        t1 = TimestampHelper.getTimestamp("Decryption started: ");
        GCMBlockCipher aes = new GCMBlockCipher(new AESEngine());
        aes.init(false, ivAndKey);
        byte[] message = cipherMessage(aes, cipher);
        t2 = TimestampHelper.getTimestamp("Decryption ended: ");
        TimestampHelper.displayTimeDistance("Decryption AES(BC) ", t1, t2);

        return new String(message, StandardCharsets.UTF_8);
    }

    public static byte[] cipherMessage(GCMBlockCipher cipher, byte[] message) throws Exception {
        //return the minimum size of the output buffer required for an update plus a doFinal with an input of len bytes.
        byte[] outputBuffer = new byte[cipher.getOutputSize(message.length)];
        //return the number of output bytes copied to outputBuffer.
        int outputBytes = cipher.doFinal(outputBuffer, cipher.processBytes(message, 0, message.length, outputBuffer, 0));
        byte[] result = new byte[outputBytes];
        System.arraycopy(outputBuffer, 0, result, 0, result.length);

        return result;
    }


    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        String plainMessage = "Plain message";
        byte[] key = generateKey(AES_KEY_SIZE);
        byte[] iv = getRandomNonce(IV_LENGTH_BYTE);
        CipherParameters ivAndKey = new ParametersWithIV(new KeyParameter(key), iv);
        byte[] encryptedMessage = encrypt(plainMessage.getBytes("UTF-8"), ivAndKey);
        String decryptedMessage = decrypt(encryptedMessage, ivAndKey);
        TimestampHelper.displayJavaRuntimeMemoryUsage();
        logger.info("Plain text was {} and decrypted text is: {}", plainMessage, decryptedMessage);
    }
}
