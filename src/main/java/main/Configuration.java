package main;

import check.*;

import java.util.ArrayList;
import java.util.HashMap;

public class Configuration {
    private final HashMap<String, String> configurationMap;
    private ArrayList<BaseChecker> ruleCheckers;

    public Configuration() {
        configurationMap = new HashMap<>();

        configurationMap.put("upperLevel", "5");
        configurationMap.put("lowerLevel", "-5");
    }

    public static Configuration getInstance() {
        return Holder.instance;
    }

    public void setArguments(String[] args) {
        for (int i = 1; i < args.length; i++) {
            String[] arg = args[i].split("=");
            configurationMap.put(arg[0], arg[1]);
        }
    }

    public String getConfig(String key) {
        return configurationMap.get(key);
    }

    public void loadRuleCheckers() {
        ruleCheckers = new ArrayList<>();

        ruleCheckers.add(new WeakAlgorithmChecker()); // rule 1
        ruleCheckers.add(new ECBModeChecker()); // rule 2
        ruleCheckers.add(new HardcodedKeyChecker()); // rule 3
        ruleCheckers.add(new StaticSaltChecker()); // rule 4
        ruleCheckers.add(new PBEIterationChecker()); // rule 5
        ruleCheckers.add(new StaticSeedsChecker()); // rule 6
        ruleCheckers.add(new PredictableIVChecker()); // rule 7
        ruleCheckers.add(new PredictableKeyChecker()); // rule 8
        ruleCheckers.add(new RSAKeySizeChecker()); // rule 9
        ruleCheckers.add(new HardcodedIVChecker()); // rule 10
        ruleCheckers.add(new RSAPaddingChecker()); // rule 11
        ruleCheckers.add(new EncryptAndMACChecker()); // rule 12
        ruleCheckers.add(new OperationModeChecker()); // rule 13
        ruleCheckers.add(new MACKeySizeChecker()); // rule 14
    }

    public ArrayList<BaseChecker> getRuleCheckers() {
        return ruleCheckers;
    }

    private static class Holder {
        private static final Configuration instance = new Configuration();
    }
}