package com.ccadroid.util.graph;

import org.graphstream.graph.Edge;
import org.graphstream.graph.Node;
import org.graphstream.graph.implementations.SingleGraph;

import java.util.ArrayList;
import java.util.List;

public class CallGraph extends BaseGraph {
    public static final String INTERFACE_NAME = "interfaceName";
    private static final String IS_CONCRETE = "isConcrete";
    private static final String LEVEL = "level";

    public CallGraph() {
        int hashCode = this.hashCode();
        String id = String.valueOf(hashCode);
        graph = new SingleGraph(id);
        graph.setAutoCreate(false);
    }

    public Node getNode(String id) {
        return super.getNode(id);
    }

    public Node addNode(String id, String label) {
        return super.addNode(id, label);
    }

    public boolean isConcrete(Node node) {
        Object attribute = node.getAttribute(IS_CONCRETE);

        return attribute != null && (boolean) attribute;
    }

    public void setConcrete(Node node, boolean isConcrete) {
        node.setAttribute(IS_CONCRETE, isConcrete);
    }

    public String getInterfaceName(Node node) {
        Object attribute = node.getAttribute(INTERFACE_NAME);

        return attribute == null ? null : (String) attribute;
    }

    public void setInterfaceName(Node node, String methodName) {
        node.setAttribute(INTERFACE_NAME, methodName);
    }

    public int getLevel(Node node) {
        Object attribute = node.getAttribute(LEVEL);

        return (int) attribute;
    }

    public void setLevel(Node node, int level) {
        node.setAttribute(CallGraph.LEVEL, level);
    }

    public void deleteNode(Node node) {
        super.deleteNode(node);
    }

    public void addEdge(Node node1, Node node2, boolean isDirected) {
        super.addEdge(node1, node2, isDirected);
    }

    public List<Edge> getEdges(Node node) {
        return super.getEdges(node);
    }

    public ArrayList<ArrayList<String>> getListOfIds(String id) {
        return super.getListOfIds(id);
    }

    @Override
    protected void traverse(Node node, ArrayList<String> ids, ArrayList<ArrayList<String>> listOfIds) {
        if (ids.isEmpty()) {
            String id = node.getId();
            ids.add(id);
        }

        boolean flag = false;
        List<Edge> edges = getEdges(node);
        for (Edge e : edges) {
            if (!e.isDirected()) {
                continue;
            }

            Node node2 = e.getSourceNode();
            String id2 = node2.getId();
            if (ids.contains(id2)) { // escape loop
                continue;
            }

            flag = true;
            ArrayList<String> tempIds = new ArrayList<>(ids);
            tempIds.add(0, id2);

            traverse(node2, tempIds, listOfIds);
        }

        if (!flag) {
            listOfIds.add(ids);
        }
    }
}