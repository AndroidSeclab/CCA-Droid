package graph;

import org.graphstream.graph.Edge;
import org.graphstream.graph.Node;
import org.graphstream.graph.implementations.SingleGraph;

import java.util.ArrayList;

public class CallGraph extends BaseGraph {

    public CallGraph() {
        graph = new SingleGraph(String.valueOf(this.hashCode()));
        graph.setAutoCreate(false);
    }

    public Node getNode(String id) {
        return super.getNode(id);
    }

    public Node addNode(String hashCode, String label, String type) {
        return super.addNode(hashCode, label, type);
    }

    public Edge getEdge(Node node1, Node node2, EdgeType type) {
        return super.getEdge(node1, node2, type);
    }

    public void addEdge(Node node1, Node node2, EdgeType type) {
        super.addEdge(node1, node2, type);
    }

    public ArrayList<ArrayList<String>> getListOfIds(String id, boolean isUpper) {
        return super.getListOfIds(id, isUpper);
    }

    public void clear() {
        super.clear();
    }
}