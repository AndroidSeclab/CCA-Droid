package com.ccadroid.slice;

import com.ccadroid.inspect.SlicingCriterion;
import com.ccadroid.util.graph.CallGraph;
import org.graphstream.graph.Node;
import org.json.JSONArray;
import org.json.JSONObject;
import soot.Value;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import static com.ccadroid.slice.SliceConstant.*;
import static com.ccadroid.util.soot.SootUnit.PARAMETER;

public class SliceMerger {
    private static final SliceDatabase sliceDatabase;
    private static final CodeOptimizer codeOptimizer;

    static {
        sliceDatabase = SliceDatabase.getInstance();
        codeOptimizer = CodeOptimizer.getInstance();
    }

    private final CallGraph callGraph;

    public SliceMerger() {
        callGraph = new CallGraph();
    }

    public static SliceMerger getInstance() {
        return SingletonHolder.instance;
    }

    public Node addNode(String hashCode, String label, int level) {
        Node node = callGraph.addNode(hashCode, label);
        callGraph.setLevel(node, level);

        return node;
    }

    public void deleteNode(Node node) {
        callGraph.deleteNode(node);
    }

    public boolean isConcrete(Node node) {
        return callGraph.isConcrete(node);
    }

    public int getLevel(Node node) {
        return callGraph.getLevel(node);
    }

    public void addEdge(Node node1, Node node2, boolean isDirected) {
        callGraph.addEdge(node1, node2, isDirected);
    }

    public Node getNode(String id) {
        return callGraph.getNode(id);
    }

    public void mergeSlices(SlicingCriterion slicingCriterion) {
        String nodeId = slicingCriterion.getId();
        List<String> query1 = List.of(String.format("%s==%s", NODE_ID, nodeId), String.format("%s==null", CALLER_NAME), String.format("%s!=null", CONTENTS));
        JSONObject mergedSlice = sliceDatabase.selectOne(query1);
        if (mergedSlice != null) {
            return;
        }

        String targetStatement = slicingCriterion.getTargetStatement();
        ArrayList<Integer> targetParamNumbers = slicingCriterion.getTargetParamNumbers();
        Collection<Value> targetVariables = slicingCriterion.getTargetVariables();
        ArrayList<ArrayList<String>> listOfIds = getListOfIds(nodeId);

        for (ArrayList<String> ids : listOfIds) {
            ArrayList<JSONObject> slices = new ArrayList<>();
            ArrayList<JSONObject> combinedContents = new ArrayList<>();

            for (String id : ids) {
                List<String> query2 = List.of(String.format("%s==%s", NODE_ID, id), String.format("%s!=null", CALLER_NAME));
                JSONObject slice = sliceDatabase.selectOne(query2);
                if (slice == null) {
                    continue;
                }

                slices.add(slice);
                JSONArray contents = slice.getJSONArray(CONTENTS);
                contents.forEach(o -> combinedContents.add((JSONObject) o));
            }

            if (combinedContents.isEmpty()) {
                continue;
            }

            codeOptimizer.removeUnreachableStatement(slices, combinedContents);

            sliceDatabase.insert(nodeId, targetStatement, targetParamNumbers, targetVariables, combinedContents);
        }
    }

    private ArrayList<ArrayList<String>> getListOfIds(String nodeId) {
        return callGraph.getListOfIds(nodeId);
    }

    private static class SingletonHolder {
        private static final SliceMerger instance = new SliceMerger();
    }
}