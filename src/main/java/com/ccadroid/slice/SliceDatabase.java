package com.ccadroid.slice;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.*;

import static com.ccadroid.slice.SliceConstants.*;

public class SliceDatabase {
    private HashMap<Integer, JSONObject> collection;

    public static SliceDatabase getInstance() {
        return SliceDatabase.Holder.instance;
    }

    public void initialize() {
        collection = new HashMap<>();
    }

    public void insert(String nodeId, ArrayList<String> relatedNodeIds, String callerName, String targetStatement, int startUnitIndex, ArrayList<Integer> targetParamNumbers, ArrayList<String> targetVariables, ArrayList<JSONObject> content) {
        JSONObject object = new JSONObject();
        object.put(NODE_ID, nodeId);
        object.put(RELATED_NODE_IDS, relatedNodeIds);
        object.put(CALLER_NAME, callerName);
        object.put(TARGET_STATEMENT, targetStatement);
        object.put(TARGET_PARAM_NUMBERS, targetParamNumbers);
        object.put(START_UNIT_INDEX, startUnitIndex);
        object.put(TARGET_VARIABLES, targetVariables);
        object.put(CONTENT, content);

        collection.put(object.hashCode(), object);
    }

    public void insert(String nodeId, String targetStatement, ArrayList<Integer> targetParamNumbers, ArrayList<String> targetVariables, ArrayList<JSONObject> content) {
        JSONObject object = new JSONObject();
        object.put(NODE_ID, nodeId);
        object.put(TARGET_STATEMENT, targetStatement);
        object.put(TARGET_PARAM_NUMBERS, targetParamNumbers);
        object.put(TARGET_VARIABLES, targetVariables);
        object.put(CONTENT, content);

        collection.put(object.hashCode(), object);
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

                if (v.equals("null")) {
                    Object r = o1.query(k);
                    flag &= ((q.contains("==") && r == null) || (q.contains("!=") && r != null));
                } else if (!q.contains(" in ")) {
                    flag &= o1.has(k) && o1.get(k).equals(v);
                } else {
                    boolean f = false;
                    ArrayList<JSONObject> objects = getValuesInObject(o1, k);
                    for (JSONObject o2 : objects) {
                        f |= o2.has(k) && (o2.get(k) instanceof String) && o2.get(k).toString().contains(v);
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

    public void update(JSONObject slice, List<String> query) {
        for (String q : query) {
            if (!q.contains("==")) {
                continue;
            }

            String[] arr = q.split("==");
            String k = arr[0];
            String v = arr[1];

            slice.put(k, v);
        }

        collection.put(slice.hashCode(), slice);
    }

    public void delete(List<String> query) {
        Collection<JSONObject> values = collection.values();

        ArrayList<JSONObject> result = selectAll(query);
        for (JSONObject o : result) {
            values.remove(o);
        }
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

    private static class Holder {
        private static final SliceDatabase instance = new SliceDatabase();
    }
}