package com.ccadroid.slice;

import org.json.JSONArray;
import org.json.JSONObject;
import soot.Value;

import java.util.*;

import static com.ccadroid.slice.SliceConstant.*;

public class SliceDatabase {
    private final HashMap<Integer, JSONObject> collection;

    public SliceDatabase() {
        collection = new HashMap<>();
    }

    public static SliceDatabase getInstance() {
        return SingletonHolder.instance;
    }

    public void insert(String nodeId) {
        JSONObject object = new JSONObject();
        object.put(NODE_ID, nodeId);

        int id = getId(object);
        collection.put(id, object);
    }

    public void insert(String nodeId, String callerName, String targetStatement, int targetUnitIndex, ArrayList<Integer> targetParamIndexes, Collection<Value> targetVariables, ArrayList<JSONObject> contents) {
        JSONObject object = new JSONObject();
        object.put(NODE_ID, nodeId);
        object.put(CALLER_NAME, callerName);
        object.put(TARGET_STATEMENT, targetStatement);
        object.put(TARGET_UNIT_INDEX, targetUnitIndex);
        object.put(TARGET_PARAM_INDEXES, targetParamIndexes);
        object.put(TARGET_VARIABLES, targetVariables.toString());
        object.put(CONTENTS, contents);

        int id = getId(object);
        collection.put(id, object);
    }

    public void insert(String nodeId, String targetStatement, ArrayList<Integer> targetParamNumbers, Collection<Value> targetVariables, ArrayList<JSONObject> contents) {
        JSONObject object = new JSONObject();
        object.put(NODE_ID, nodeId);
        object.put(TARGET_STATEMENT, targetStatement);
        object.put(TARGET_PARAM_INDEXES, targetParamNumbers);
        object.put(TARGET_VARIABLES, targetVariables.toString());
        object.put(CONTENTS, contents);

        int id = getId(object);
        collection.put(id, object);
    }

    public ArrayList<JSONObject> selectAll(List<String> query) {
        HashSet<JSONObject> result = new HashSet<>();

        ArrayList<JSONObject> values = new ArrayList<>(collection.values());
        for (JSONObject o1 : values) {
            boolean flag = true;

            for (String q : query) {
                String[] arr = q.split("(==)|(!=)|( in )");
                String k = arr[0];
                String v = arr[1];

                if ((q.contains("==") || q.contains("!=")) && !v.equals("null")) {
                    flag &= o1.has(k) && ((q.contains("==") && o1.get(k).equals(v)) || (q.contains("!=") && !o1.get(k).equals(v)));
                } else if ((q.contains("==") || q.contains("!=")) && v.equals("null")) {
                    Object r = o1.query(String.format("/%s", k));
                    flag &= ((q.contains("==") && r == null) || (q.contains("!=") && r != null));
                } else if (q.contains(" in ")) {
                    boolean f = false;
                    ArrayList<JSONObject> objects = getValuesInObject(o1, v);
                    for (JSONObject o2 : objects) {
                        f |= o2.has(v) && (o2.get(v) instanceof String) && o2.get(v).toString().contains(k);
                    }

                    flag &= f;
                }
            }

            if (flag) {
                result.add(o1);
            }
        }

        return new ArrayList<>(result);
    }

    public JSONObject selectOne(List<String> query) {
        ArrayList<JSONObject> result = selectAll(query);

        return (result.isEmpty()) ? null : result.get(0);
    }

    public void delete(String nodeId) {
        List<String> query = List.of(String.format("%s==%s", NODE_ID, nodeId), String.format("%s==null", CONTENTS));
        ArrayList<JSONObject> result = selectAll(query);
        Collection<JSONObject> values = collection.values();

        for (JSONObject o : result) {
            values.remove(o);
        }
    }

    private int getId(JSONObject object) {
        return object.hashCode();
    }

    private ArrayList<JSONObject> getValuesInObject(JSONObject jsonObject, String key) {
        ArrayList<JSONObject> objects = new ArrayList<>();

        for (String k : jsonObject.keySet()) {
            Object o = jsonObject.get(k);
            if (k.equals(key)) {
                objects.add(jsonObject);
            }

            if (o instanceof JSONObject) {
                objects.addAll(getValuesInObject((JSONObject) o, key));
            } else if (o instanceof JSONArray) {
                objects.addAll(getValuesInArray((JSONArray) o, key));
            }
        }

        return objects;
    }

    private ArrayList<JSONObject> getValuesInArray(JSONArray jsonArray, String key) {
        ArrayList<JSONObject> objects = new ArrayList<>();

        for (Object o : jsonArray) {
            if (o instanceof JSONArray) {
                objects.addAll(getValuesInArray((JSONArray) o, key));
            } else if (o instanceof JSONObject) {
                objects.addAll(getValuesInObject((JSONObject) o, key));
            }
        }

        return objects;
    }

    private static class SingletonHolder {
        private static final SliceDatabase instance = new SliceDatabase();
    }
}