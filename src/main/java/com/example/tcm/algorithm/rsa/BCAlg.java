package com.example.tcm.algorithm.rsa;

import com.example.tcm.helper.Helper;
import com.example.tcm.helper.TimestampHelper;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;


public class BCAlg extends RSA {

    public static AsymmetricCipherKeyPair getKey() throws NoSuchAlgorithmException {
        RSAKeyPairGenerator generator = new RSAKeyPairGenerator();
        generator.init(new RSAKeyGenerationParameters
                (
                        new BigInteger("10001", 16),//publicExponent
                        SecureRandom.getInstance("SHA1PRNG"),//pseudorandom number generator
                        RSA_KEY_SIZE,//strength
                        80//certainty
                ));
        t1 = TimestampHelper.getTimestamp("Key Pair Generation started: ");
        AsymmetricCipherKeyPair keyPair = generator.generateKeyPair();
        t2 = TimestampHelper.getTimestamp("Key Pair Generation ended: ");
        TimestampHelper.displayTimeDistance("Key pair generation(BC) ", t1, t2);

        return keyPair;
    }

    public static String encrypt(byte[] data, AsymmetricKeyParameter publicKey) {
        t1 = TimestampHelper.getTimestamp("Encryption started: ");
        RSAEngine engine = new RSAEngine();
        engine.init(true, publicKey); //true if encrypt
        byte[] hexEncodedCipher = engine.processBlock(data, 0, data.length);
        t2 = TimestampHelper.getTimestamp("Encryption ended: ");
        TimestampHelper.displayTimeDistance("Encryption RSA(BC) ", t1, t2);

        return Helper.getHexString(hexEncodedCipher);
    }

    public static String decrypt(String encrypted, AsymmetricKeyParameter privateKey) throws InvalidCipherTextException {
        t1 = TimestampHelper.getTimestamp("Decryption started: ");
        AsymmetricBlockCipher engine = new RSAEngine();
        engine.init(false, privateKey); //false for decryption

        byte[] encryptedBytes = Helper.hexStringToByteArray(encrypted);
        byte[] hexEncodedCipher = engine.processBlock(encryptedBytes, 0, encryptedBytes.length);
        t2 = TimestampHelper.getTimestamp("Decryption ended: ");
        TimestampHelper.displayTimeDistance("Decryption RSA(BC) ", t1, t2);

        return new String(hexEncodedCipher);
    }

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        String plainMessage = "Plain message";
        AsymmetricCipherKeyPair asymmetricCipherKeyPair = BCAlg.getKey();
        String encryptedMessage = encrypt(plainMessage.getBytes(StandardCharsets.UTF_8), asymmetricCipherKeyPair.getPublic());
        logger.info(encryptedMessage);
        String decryptedMessage = decrypt(encryptedMessage, asymmetricCipherKeyPair.getPrivate());
        TimestampHelper.displayJavaRuntimeMemoryUsage();
        logger.info("Plain message was: {}  and decrypted message is: {} ", plainMessage, decryptedMessage);
    }

}
