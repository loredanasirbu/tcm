package com.example.tcm.helper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Timestamp;
import java.util.Date;

public class TimestampHelper {
    private static final Logger logger = LoggerFactory.getLogger(TimestampHelper.class);

    private TimestampHelper() {
        throw new IllegalStateException("Utility class");
    }

    public static Timestamp getTimestamp(String info) {

        Timestamp time = new Timestamp((new Date()).getTime());
        logger.info("{} {}", info, time);
        return time;
    }

    public static void displayTimeDistance(String method, Timestamp t1, Timestamp t2) {
        logger.info("{}took {} ms \n", method, (t2.getTime() - t1.getTime()));
    }

    public static void displayJavaRuntimeMemoryUsage() {
        Runtime rt = Runtime.getRuntime();
        long prevTotal = 0;
        long prevFree = rt.freeMemory();

        for (int i = 0; i < 2_000_000; i++) {
            long total = rt.totalMemory();
            long free = rt.freeMemory();
            long processor = rt.availableProcessors();
            if (total != prevTotal || free != prevFree) {
                long used = total - free;
                System.out.println(
                        "#" + i +
                                ", Total: " + convertBytes(total) +
                                ", Processors: " + processor +
                                ", Used: " + convertBytes(used) +
                                ", Free: " + convertBytes(free));
                prevTotal = total;
                prevFree = free;
            }

        }
    }

    private static String convertBytes(long bytes) {
        String cnt_size;

        double size_kb = bytes / 1024;
        double size_mb = size_kb / 1024;
        double size_gb = size_mb / 1024;

        if (size_gb > 1) {
            cnt_size = size_gb + " GB";
        } else if (size_mb > 1) {
            cnt_size = size_mb + " MB";
        } else {
            cnt_size = size_kb + " KB";
        }
        return cnt_size;
    }
}
