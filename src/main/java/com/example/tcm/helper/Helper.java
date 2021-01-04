package com.example.tcm.helper;

import java.util.ArrayList;
import java.util.List;

public class Helper {
    //    private static Logger logger = LoggerFactory.getLogger(Helper.class);
    private Helper() {
        throw new IllegalStateException("Utility class");
    }

    public static String getHexString(byte[] b) {
        StringBuilder bld = new StringBuilder();
        for (int i = 0; i < b.length; i++) {
            bld.append(
                    Integer.toString((b[i] & 0xff) + 0x100, 16).substring(1));
        }
        return String.valueOf(bld);
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    // hex representation
    public static String hex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }

    // print hex with block size split
    public static String hexWithBlockSize(byte[] bytes, int blockSize) {

        String hex = hex(bytes);

        // one hex = 2 chars
        blockSize = blockSize * 2;

        List<String> result = new ArrayList<>();
        int index = 0;
        while (index < hex.length()) {
            result.add(hex.substring(index, Math.min(index + blockSize, hex.length())));
            index += blockSize;
        }

        return result.toString();

    }

    public static void printByteArr(byte[] arr) {
        System.out.print("[");
        for (int i = 0; i < arr.length; i++) {
            System.out.printf(i == 0 ? "%d" : ",%d", (arr[i] & 0xFF));
        }
        System.out.println("]");
    }
}
