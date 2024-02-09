package com.ccadroid.util.graph;

import org.graphstream.graph.Edge;
import org.graphstream.graph.Graph;
import org.graphstream.graph.Node;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public abstract class BaseGraph {
    protected Graph graph;

    public BaseGraph() {
        System.setProperty("org.graphstream.ui", "javafx");
    }

    protected Node addNode(String id, String label) {
        Node node = graph.getNode(id);
        if (node == null) {
            node = graph.addNode(id);
        }

        node.setAttribute("label", label);

        return node;
    }

    protected void addEdge(Node node1, Node node2, EdgeType type) {
        String id = getEdgeId(node1, node2, type);
        Edge edge = graph.getEdge(id);
        if (edge != null) {
            return;
        }

        if (type == EdgeType.UPWARD) {
            edge = graph.addEdge(id, node2, node1, true);
        } else if (type == EdgeType.DOWNWARD) {
            edge = graph.addEdge(id, node1, node2, true);
        } else {
            edge = graph.addEdge(id, node1, node2, false);
        }

        edge.setAttribute("ui.class", type);
    }

    protected Node getNode(String id) {
        return graph.getNode(id);
    }

    protected List<Edge> getEdges(Node node) {
        Stream<Edge> stream = node.edges();

        return stream.collect(Collectors.toList());
    }

    protected Edge getEdge(Node node1, Node node2, EdgeType type) {
        String id = getEdgeId(node1, node2, type);
        Edge edge = graph.getEdge(id);
        if (edge == null) {
            return null;
        }

        Object attribute = edge.getAttribute("ui.class");

        return attribute.equals(type) ? edge : null;
    }

    protected ArrayList<ArrayList<String>> getListOfIds(String id, boolean isUpper) {
        Node node = graph.getNode(id);
        if (node == null) {
            return new ArrayList<>();
        }

        ArrayList<String> ids = new ArrayList<>();
        ArrayList<ArrayList<String>> listOfIds = new ArrayList<>();
        traverse(node, ids, listOfIds, isUpper);

        if (listOfIds.isEmpty()) {
            listOfIds.add(ids);
        }

        return listOfIds;
    }

    private String getEdgeId(Node node1, Node node2, EdgeType type) {
        String id;
        if (type == EdgeType.UPWARD) {
            id = node2.getId() + "-->" + node1.getId();
        } else if (type == EdgeType.DOWNWARD) {
            id = node1.getId() + "-->" + node2.getId();
        } else {
            String id1 = node1.getId() + "---" + node2.getId();
            String id2 = node2.getId() + "---" + node1.getId();
            id = (graph.getEdge(id1) == null) ? id2 : id1;
        }

        return id;
    }

    private void traverse(Node node, ArrayList<String> ids, ArrayList<ArrayList<String>> listOfIds, boolean isUpper) {
        if (ids.isEmpty()) {
            String id = node.getId();
            ids.add(id);
        }

        boolean flag = false;
        List<Edge> edges = getEdges(node);
        for (Edge e : edges) {
            Node node2 = isUpper ? e.getSourceNode() : e.getTargetNode();
            String id2 = node2.getId();
            if (ids.contains(id2)) { // escape loop
                continue;
            }

            flag = true;
            ArrayList<String> tempIds = new ArrayList<>(ids);
            if (isUpper) {
                tempIds.add(0, id2);
            } else {
                tempIds.add(id2);
            }

            traverse(node2, tempIds, listOfIds, isUpper);
        }

        if (!flag) {
            listOfIds.add(ids);
        }
    }

    public enum EdgeType {
        READ, WRITE, UPWARD, DOWNWARD, NONE
    }
}