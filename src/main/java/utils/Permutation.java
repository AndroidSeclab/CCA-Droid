package utils;

import java.util.ArrayList;

public class Permutation {

    public static ArrayList<int[]> getAllCases(int n, int r) {
        int[] arr;

        if (n == 1) {
            arr = new int[r];
            for (int i = 0; i < r; i++) {
                arr[i] = 0;
            }
        } else {
            arr = new int[n];
            for (int i = 0; i < n; i++) {
                arr[i] = i;
            }
        }

        int[] output = new int[n];
        boolean[] visited = new boolean[n];
        ArrayList<int[]> cases = new ArrayList<>();
        if (n == 1) {
            cases.add(arr);
        } else {
            permutation(arr, output, visited, 0, n, r, cases);
        }

        return cases;
    }

    private static void permutation(int[] arr, int[] output, boolean[] visited, int depth, int n, int r, ArrayList<int[]> cases) {
        if (depth == r) {
            int[] arr2 = new int[r];
            System.arraycopy(output, 0, arr2, 0, r);
            cases.add(arr2);
            return;
        }

        for (int i = 0; i < n; i++) {
            if (!visited[i]) {
                visited[i] = true;
                output[depth] = arr[i];

                permutation(arr, output, visited, depth + 1, n, r, cases);
                visited[i] = false;
            }
        }
    }
}