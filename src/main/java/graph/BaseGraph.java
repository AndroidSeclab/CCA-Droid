package graph;

import org.graphstream.graph.Edge;
import org.graphstream.graph.Graph;
import org.graphstream.graph.Node;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static java.util.stream.Collectors.toList;

public abstract class BaseGraph {
    protected Graph graph;

    public BaseGraph() {
        System.setProperty("org.graphstream.ui", "javafx");
    }

    protected Node addNode(String id, String label, String type) {
        Node node = graph.getNode(id);
        if (node == null) {
            node = graph.addNode(id);
        }

        node.setAttribute("label", label);
        node.setAttribute("ui.class", type);
        return node;
    }

    protected Edge getEdge(Node node1, Node node2, EdgeType type) {
        String id = node1.getId() + "-->" + node2.getId();
        Edge edge = graph.getEdge(id);
        if (edge == null) {
            return null;
        }

        return edge.getAttribute("ui.class").equals(type) ? edge : null;
    }

    protected void addEdge(Node node1, Node node2, EdgeType type) {
        String id = node1.getId() + "-->" + node2.getId();
        Edge edge = graph.getEdge(id);
        if (edge != null) {
            return;
        }

        edge = graph.addEdge(id, node1, node2, true);
        edge.setAttribute("ui.class", type);
    }

    protected Node getNode(String id) {
        return graph.getNode(id);
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

    protected void clear() {
        graph.clear();
    }

    private void traverse(Node node, ArrayList<String> ids, ArrayList<ArrayList<String>> listOfIds, boolean isUpper) {
        if (ids.isEmpty()) {
            String id = node.getId();
            ids.add(id);
        }

        boolean flag = false;
        Stream<Edge> stream = node.edges();
        List<Edge> edges = stream.collect(toList());
        for (Edge e : edges) {
            Node node2 = (isUpper) ? e.getSourceNode() : e.getTargetNode();
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
        READ, WRITE, UPWARD, DOWNWARD
    }
}