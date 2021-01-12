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
        timer.start();
        AsymmetricCipherKeyPair keyPair = generator.generateKeyPair();
        logger.info("Key generation took {} ", timer.stop());
        return keyPair;
    }

    public static String encrypt(AsymmetricBlockCipher engine, byte[] data, AsymmetricKeyParameter publicKey) throws InvalidCipherTextException {
        engine.init(true, publicKey); //true if encrypt
        timer.start();
        byte[] hexEncodedCipher = engine.processBlock(data, 0, data.length);
        logger.info("Encrypt took {} ", timer.stop());

        return Helper.getHexString(hexEncodedCipher);
    }

    public static String decrypt(AsymmetricBlockCipher engine, String encrypted, AsymmetricKeyParameter privateKey) throws InvalidCipherTextException {
        engine.init(false, privateKey);
        byte[] encryptedBytes = Helper.hexStringToByteArray(encrypted);
        timer.start();
        byte[] hexEncodedCipher = engine.processBlock(encryptedBytes, 0, encryptedBytes.length);
        logger.info("Decrypt took {} ", timer.stop());
        return new String(hexEncodedCipher);
    }

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        AsymmetricBlockCipher engine = new RSAEngine();
        String plainMessage = "Before the modern era, cryptography focused on message confidentiality (i.e., encryption)—conversion of messages from a comprehensible form into an incomprehensible one and back again at the other end, rendering it unreadable by interceptors or eavesdroppers without secret knowledge (namely the key needed for decryption of that message). Encryption attempted to ensure secrecy in communications, such as those of spies, military leaders, and diplomats. ";
        AsymmetricCipherKeyPair asymmetricCipherKeyPair = getKey();
        String encryptedMessage = encrypt(engine, plainMessage.getBytes(StandardCharsets.UTF_8), asymmetricCipherKeyPair.getPublic());
        String decryptedMessage = decrypt(engine, encryptedMessage, asymmetricCipherKeyPair.getPrivate());
        TimestampHelper.displayJavaRuntimeMemoryUsage();
        logger.info("Before the modern era, cryptography focused on message confidentiality (i.e., encryption)—conversion of messages from a comprehensible form into an incomprehensible one and back again at the other end, rendering it unreadable by interceptors or eavesdroppers without secret knowledge (namely the key needed for decryption of that message). Encryption attempted to ensure secrecy in communications, such as those of spies, military leaders, and diplomats. In recent decades, the field has expanded beyond confidentiality concerns to include techniques for message integrity checking, sender/receiver identity authentication, digital signatures, interactive proofs and secure computation, among others. was: {}  and decrypted message is: {} ", plainMessage, decryptedMessage);
    }

}
