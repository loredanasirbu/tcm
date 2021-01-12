package com.example.tcm.algorithm.rsa;

import com.google.common.base.Stopwatch;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class RSA {

    protected static Stopwatch timer = Stopwatch.createUnstarted();
    protected static final Logger logger = LoggerFactory.getLogger(RSA.class);
    protected static final int RSA_KEY_SIZE = 4096;
}
