package com.example.tcm.helper;

public class Helper {
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
}
