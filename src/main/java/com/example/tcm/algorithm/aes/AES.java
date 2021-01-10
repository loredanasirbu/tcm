package com.example.tcm.algorithm.aes;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.SecureRandom;
import java.sql.Timestamp;

public class AES {
    protected static final String ENCRYPT_ALGO = "AES/GCM/NoPadding";
    protected static final int TAG_LENGTH_BIT = 128;
    protected static final int IV_LENGTH_BYTE = 16;
    protected static final int AES_KEY_SIZE = 256;
    protected static Timestamp t1;
    protected static Timestamp t2;
    protected static final Logger logger = LoggerFactory.getLogger(AES.class);

    protected static byte[] getRandomNonce(int numBytes) {
        byte[] nonce = new byte[numBytes];
        new SecureRandom().nextBytes(nonce);

        return nonce;
    }
}
