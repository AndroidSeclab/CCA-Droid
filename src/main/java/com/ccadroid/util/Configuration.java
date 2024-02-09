package com.ccadroid.util;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class Configuration {
    private static Properties prop;

    public static void loadConfig() {
        try {
            ClassLoader classLoader = Configuration.class.getClassLoader();
            InputStream inputStream = classLoader.getResourceAsStream("config.properties");
            if (inputStream == null) {
                throw new IOException();
            }

            BufferedInputStream bis = new BufferedInputStream(inputStream);

            prop = new Properties();
            prop.load(bis);
        } catch (IOException e) {
            System.out.println("[*] ERROR: " + e.getMessage());
            System.exit(1);
        }
    }

    public static String getProperty(String key) {
        return prop.getProperty(key);
    }
}