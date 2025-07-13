package com.ccadroid.util;

import org.apache.commons.lang3.math.NumberUtils;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;

public class Common {

    public Common() throws InstantiationException {
        throw new InstantiationException();
    }

    public static void printf(Class<?> clazz, Object message) {
        System.out.printf("[*] %s(): %s\n", clazz.getName(), message);
    }

    public static void printToFile(String filePath, ArrayList<String> lines) {
        try {
            FileWriter fileWriter = new FileWriter(filePath, true);
            BufferedWriter bufferedWriter = new BufferedWriter(fileWriter);
            for (String l : lines) {
                bufferedWriter.write(l);
            }

            bufferedWriter.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static boolean isNumber(String str) {
        return NumberUtils.isCreatable(str);
    }
}