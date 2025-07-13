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

    protected Node getNode(String id) {
        return graph.getNode(id);
    }

    protected Node addNode(String id, String label) {
        Node node = (graph.getNode(id) == null) ? graph.addNode(id) : graph.getNode(id);
        node.setAttribute("label", label);

        return node;
    }

    protected void deleteNode(Node node) {
        if (node == null) {
            return;
        }

        graph.removeNode(node);
    }

    protected ArrayList<ArrayList<String>> getListOfIds(String id) {
        Node node = graph.getNode(id);
        if (node == null) {
            return new ArrayList<>();
        }

        ArrayList<String> ids = new ArrayList<>();
        ArrayList<ArrayList<String>> listOfIds = new ArrayList<>();
        traverse(node, ids, listOfIds);

        if (listOfIds.isEmpty()) {
            listOfIds.add(ids);
        }

        return listOfIds;
    }

    protected void addEdge(Node node1, Node node2, boolean isDirected) {
        Edge edge = getEdge(node1, node2, isDirected);

        if (edge == null) {
            String id = getEdgeId(node1, node2, isDirected);
            graph.addEdge(id, node1, node2, isDirected);
        }
    }

    protected List<Edge> getEdges(Node node) {
        Stream<Edge> stream = node.edges();

        return stream.collect(Collectors.toList());
    }

    protected String getGraphString() {
        StringBuilder builder = new StringBuilder("digraph {");
        builder.append("\n");

        Stream<Edge> stream = graph.edges();
        List<Edge> edges = stream.collect(Collectors.toList());
        for (Edge e : edges) {
            builder.append("\t");

            String edgeId = e.getId();
            if (e.isDirected()) {
                builder.append(edgeId);
            } else {
                String tempId = edgeId.replace("--", "->");
                builder.append(tempId);
                builder.append(" [dir=none]");
            }

            builder.append("\n");
        }

        builder.append("}");

        return builder.toString();
    }

    protected abstract void traverse(Node node, ArrayList<String> ids, ArrayList<ArrayList<String>> listOfIds);

    private Edge getEdge(Node node1, Node node2, boolean isDirected) {
        if (isDirected) {
            String id = getEdgeId(node1, node2, true);

            return graph.getEdge(id);
        } else {
            String id1 = getEdgeId(node1, node2, false);
            String id2 = getEdgeId(node2, node1, false);
            Edge edge1 = graph.getEdge(id1);
            Edge edge2 = graph.getEdge(id2);

            return (edge1 == null && edge2 == null) ? null : (edge1 == null) ? edge2 : edge1;
        }
    }

    private String getEdgeId(Node node1, Node node2, boolean isDirected) {
        String id1 = node1.getId();
        String id2 = node2.getId();

        return (isDirected) ? String.format("%s -> %s", id1, id2) : String.format("%s -- %s", id1, id2);
    }
}