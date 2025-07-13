package com.ccadroid.util;

import com.opencsv.CSVReader;
import com.opencsv.exceptions.CsvValidationException;

import java.io.IOException;
import java.io.StringReader;
import java.util.ArrayList;

public class OpenCSV {

    public OpenCSV() throws InstantiationException {
        throw new InstantiationException();
    }

    public static ArrayList<String> convertToList(String str) {
        ArrayList<String> list = new ArrayList<>();

        try {
            StringReader stringReader = new StringReader(str);
            CSVReader csvReader = new CSVReader(stringReader);
            String[] tokens = csvReader.readNext();
            for (String t : tokens) {
                t = t.trim();
                t = t.replace("\"", "");

                list.add(t);
            }
        } catch (IOException | CsvValidationException | NullPointerException ignored) {

        }

        return list;
    }
}