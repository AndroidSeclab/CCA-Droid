package com.ccadroid.util.graph;

import org.graphstream.graph.Edge;
import org.graphstream.graph.Node;
import org.graphstream.graph.implementations.SingleGraph;

import java.util.ArrayList;
import java.util.List;

import static com.ccadroid.util.graph.BaseGraph.EdgeType.*;

public class CallGraph extends BaseGraph {
    public static final String LEVEL = "level";

    public CallGraph() {
        int hashCode = this.hashCode();
        String id = String.valueOf(hashCode);
        graph = new SingleGraph(id);
        graph.setAutoCreate(false);
    }

    public Node addNode(String hashCode, String label) {
        return super.addNode(hashCode, label);
    }

    public void addEdge(Node node1, Node node2, EdgeType type) {
        super.addEdge(node1, node2, type);
    }

    public Node getNode(String id) {
        return super.getNode(id);
    }

    public List<Edge> getEdges(Node node) {
        return super.getEdges(node);
    }

    public boolean hasEdge(Node node1, Node node2) {
        Edge edge1 = getEdge(node1, node2, UPWARD);
        Edge edge2 = getEdge(node2, node1, UPWARD);
        Edge edge3 = getEdge(node1, node2, DOWNWARD);
        Edge edge4 = getEdge(node2, node1, DOWNWARD);
        Edge edge5 = getEdge(node1, node2, NONE);
        Edge edge6 = getEdge(node2, node1, NONE);

        return edge1 != null || edge2 != null || edge3 != null || edge4 != null || edge5 != null || edge6 != null;
    }

    public Edge getEdge(Node node1, Node node2, EdgeType type) {
        return super.getEdge(node1, node2, type);
    }

    public ArrayList<ArrayList<String>> getListOfIds(String id, boolean isUpper) {
        return super.getListOfIds(id, isUpper);
    }
}