package com.ccadroid.util;

import net.sourceforge.argparse4j.ArgumentParsers;
import net.sourceforge.argparse4j.inf.ArgumentParser;
import net.sourceforge.argparse4j.inf.ArgumentParserException;
import net.sourceforge.argparse4j.inf.Namespace;

public class Argparse4j {
    public static final String INPUT_PATH = "INPUT_PATH";
    public static final String PLATFORMS_PATH = "PLATFORMS_PATH";
    public static final String RULE_PATH = "RULE_PATH";
    public static final String DETECT_DEV_ONLY = "DETECT_DEV_ONLY";
    public static final String UPPER_LEVEL = "UPPER_LEVEL";
    public static final String LOWER_LEVEL = "LOWER_LEVEL";
    public static final String OUTPUT_PATH = "OUTPUT_PATH";
    private static final ArgumentParser parser;
    private static Namespace namespace;

    static {
        parser = ArgumentParsers.newFor("prog").build();
        parser.addArgument("-i", String.format("--%s", INPUT_PATH)).type(String.class).required(true);
        parser.addArgument("-p", String.format("--%s", PLATFORMS_PATH)).type(String.class).required(true);
        parser.addArgument("-r", String.format("--%s", RULE_PATH)).type(String.class).required(true);
        parser.addArgument("-s", String.format("--%s", DETECT_DEV_ONLY)).type(Boolean.class).setDefault(false);
        parser.addArgument("-ul", String.format("--%s", UPPER_LEVEL)).type(Integer.class).setDefault(5);
        parser.addArgument("-ll", String.format("--%s", LOWER_LEVEL)).type(Integer.class).setDefault(-5);
        parser.addArgument("-o", String.format("--%s", OUTPUT_PATH)).type(String.class);
    }

    public Argparse4j() throws InstantiationException {
        throw new InstantiationException();
    }

    public static String getString(String dest) {
        return namespace.getString(dest);
    }

    public static int getInt(String dest) {
        return namespace.getInt(dest);
    }

    public static void setArguments(String[] args) {
        try {
            namespace = parser.parseArgs(args);
        } catch (ArgumentParserException e) {
            throw new RuntimeException(e);
        }
    }
}