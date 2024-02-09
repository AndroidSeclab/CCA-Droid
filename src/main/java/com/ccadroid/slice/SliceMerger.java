package com.ccadroid.slice;

import com.ccadroid.inspect.SlicingCriterion;
import com.ccadroid.util.graph.BaseGraph.EdgeType;
import com.ccadroid.util.graph.CallGraph;
import org.graphstream.graph.Edge;
import org.graphstream.graph.Node;
import org.json.JSONArray;
import org.json.JSONObject;
import soot.Unit;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import static com.ccadroid.slice.SliceConstants.*;
import static com.ccadroid.util.graph.BaseGraph.EdgeType.DOWNWARD;
import static com.ccadroid.util.graph.BaseGraph.EdgeType.NONE;
import static com.ccadroid.util.graph.CallGraph.LEVEL;
import static com.ccadroid.util.soot.SootUnit.*;

public class SliceMerger {
    private final SliceDatabase sliceDatabase;
    private final SliceOptimizer sliceOptimizer;
    private final CallGraph callGraph;

    public SliceMerger() {
        sliceDatabase = SliceDatabase.getInstance();
        sliceOptimizer = SliceOptimizer.getInstance();

        callGraph = new CallGraph();
    }

    public static SliceMerger getInstance() {
        return SliceMerger.Holder.instance;
    }

    public Node addNode(String hashCode, String label, int level) {
        Node node = callGraph.addNode(hashCode, label);
        node.setAttribute(LEVEL, level);

        return node;
    }

    public List<Edge> getEdges(Node node) {
        return callGraph.getEdges(node);
    }

    public boolean hasEdges(Node node1, Node node2) {
        return callGraph.hasEdge(node1, node2);
    }

    public void addEdge(Node node1, Node node2, EdgeType type) {
        callGraph.addEdge(node1, node2, type);
    }

    public Node getNode(String id) {
        return callGraph.getNode(id);
    }

    public ArrayList<String> getRelatedNodeIds(String id) {
        ArrayList<String> ids = new ArrayList<>();
        Node node = getNode(id);
        if (node == null) {
            return ids;
        }

        List<Edge> edges1 = getEdges(node);
        for (Edge e1 : edges1) {
            EdgeType edgeType = (EdgeType) e1.getAttribute("ui.class");
            if (node == e1.getTargetNode() && edgeType == DOWNWARD) {
                continue;
            }

            Node opposite = e1.getOpposite(node);
            String oppositeId;
            if (edgeType == NONE) {
                List<Edge> edges2 = getEdges(opposite);
                for (Edge e2 : edges2) {
                    if (e1 == e2) {
                        continue;
                    }

                    Node source = e2.getSourceNode();
                    oppositeId = source.getId();
                    ids.add(oppositeId);
                    break;
                }
            } else {
                oppositeId = opposite.getId();
                ids.add(oppositeId);
            }
        }

        return ids;
    }

    public void mergeSlices(SlicingCriterion slicingCriterion) {
        String nodeId = String.valueOf(slicingCriterion.hashCode());
        List<String> query1 = List.of(String.format("%s==%s", NODE_ID, nodeId), String.format("/%s==null", CALLER_NAME));
        JSONObject mergedSlice = sliceDatabase.selectOne(query1);
        if (mergedSlice != null) {
            return;
        }

        String targetStatement = slicingCriterion.getTargetStatement();
        ArrayList<Integer> targetParamNumbers = slicingCriterion.getTargetParamNumbers();
        ArrayList<String> targetVariables = convertToStrings(slicingCriterion.getTargetVariables());

        ArrayList<ArrayList<String>> listOfIds = callGraph.getListOfIds(nodeId, true);
        for (ArrayList<String> ids : listOfIds) {
            ArrayList<JSONObject> slices = new ArrayList<>();
            ArrayList<JSONObject> mergedContent = new ArrayList<>();

            for (String id : ids) {
                List<String> query2 = List.of(String.format("%s==%s", NODE_ID, id), String.format("/%s!=null", CALLER_NAME));
                JSONObject slice = sliceDatabase.selectOne(query2);
                if (slice == null) {
                    continue;
                }

                slices.add(slice);
                JSONArray content = slice.getJSONArray(CONTENT);
                for (Object o : content) {
                    mergedContent.add((JSONObject) o);
                }
            }

            if (mergedContent.isEmpty()) {
                continue;
            }

            if (isStartingParameter(mergedContent)) {
                continue;
            }

            if (ids.size() > 1) {
                ArrayList<JSONObject> unreachables = sliceOptimizer.getUnreachableLines(slices);
                mergedContent.removeAll(unreachables);
                removeUnreachableSlices(unreachables);

                HashMap<Unit, Unit> updates = sliceOptimizer.getInterpretedUnits(slices);
                sliceOptimizer.updateLines(updates, mergedContent);
            }

            sliceDatabase.insert(nodeId, targetStatement, targetParamNumbers, targetVariables, mergedContent);
        }
    }

    private boolean isStartingParameter(ArrayList<JSONObject> slice) {
        JSONObject line = slice.get(0);
        int unitType = line.getInt(UNIT_TYPE);

        return (unitType == PARAMETER);
    }

    private void removeUnreachableSlices(ArrayList<JSONObject> unreachables) {
        for (JSONObject l : unreachables) {
            String unitStr = l.getString(UNIT_STRING);
            int unitType = l.getInt(UNIT_TYPE);
            String callerName = null;
            String targetStatement = null;

            if ((unitType & INVOKE) == INVOKE) {
                callerName = getSignature(unitStr);
                targetStatement = "return";
            } else if (unitType == ASSIGN_SIGNATURE_CONSTANT) {
                callerName = l.getString(CALLER_NAME);
                targetStatement = getSignature(unitStr);
            }

            if (callerName == null) {
                continue;
            }

            List<String> query = List.of(String.format("%s==%s", CALLER_NAME, callerName), String.format("%s==%s", TARGET_STATEMENT, targetStatement));
            sliceDatabase.delete(query);
        }

    }

    private static class Holder {
        private static final SliceMerger instance = new SliceMerger();
    }
}