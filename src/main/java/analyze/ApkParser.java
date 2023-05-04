package analyze;

import net.dongliu.apk.parser.ApkFile;
import net.dongliu.apk.parser.bean.DexClass;
import org.w3c.dom.*;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.util.ArrayList;

public class ApkParser {
    private final ArrayList<String> dexClassNames;
    private final ArrayList<String> androidComponents;
    private ApkFile apkFile;
    private String packageName;
    private String applicationClassName;

    private ApkParser() {
        androidComponents = new ArrayList<>();
        dexClassNames = new ArrayList<>();
    }

    public static ApkParser getInstance() {
        return Holder.instance;
    }

    public void initialize(String apkPath) {
        try {
            File file = new File(apkPath);
            apkFile = new ApkFile(file);
        } catch (IOException e) {
            System.out.println("[*] ERROR : '" + apkPath + "' does not exist!");
            System.exit(1);
        }
    }

    public void parseManifest() {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            String manifestXml = apkFile.getManifestXml();
            Document document = builder.parse(new InputSource(new StringReader(manifestXml)));
            Element root = document.getDocumentElement();

            packageName = root.getAttribute("package");

            NodeList childNodes = root.getChildNodes();
            int nodeCount = childNodes.getLength();
            Node appNode = null;
            for (int i = 1; i < nodeCount; i++) {
                Node node = childNodes.item(i);
                String nodeName = node.getNodeName();
                if (!nodeName.equals("application")) {
                    continue;
                }

                appNode = node;
                NamedNodeMap appNodeAttrs = appNode.getAttributes();
                int attrCount = appNodeAttrs.getLength();
                for (int j = 0; j < attrCount; j++) {
                    Node attribute = appNodeAttrs.item(j);
                    String attrName = attribute.getNodeName();
                    if (!attrName.contains("name")) {
                        continue;
                    }

                    applicationClassName = attribute.getNodeValue();
                    break;
                }
            }

            if (appNode == null) {
                return;
            }

            childNodes = appNode.getChildNodes();
            nodeCount = childNodes.getLength();
            for (int i = 1; i < nodeCount; i++) {
                Node node = childNodes.item(i);
                if (node == null) {
                    continue;
                }

                String nodeName = node.getNodeName();
                if (!nodeName.equals("activity") && !nodeName.equals("service") && !nodeName.equals("provider") && !nodeName.equals("receiver")) {
                    continue;
                }

                NamedNodeMap comNodeAttrs = node.getAttributes();
                int attrCount = comNodeAttrs.getLength();
                for (int j = 0; j < attrCount; j++) {
                    Node attribute = comNodeAttrs.item(j);
                    String attrName = attribute.getNodeName();
                    if (!attrName.contains("name")) {
                        continue;
                    }

                    String attrValue = attribute.getNodeValue();
                    androidComponents.add(attrValue);
                }
            }
        } catch (IOException | ParserConfigurationException | SAXException e) {
            System.out.println("[*] ERROR : Cannot parse AndroidManifest.xml of this apk!");
        }
    }

    public String getPackageName() {
        return packageName;
    }

    public String getApplicationClassName() {
        return applicationClassName;
    }

    public ArrayList<String> getAndroidComponents() {
        return androidComponents;
    }

    public ArrayList<String> getDexClassNames() {
        if (!dexClassNames.isEmpty()) {
            return dexClassNames;
        }

        try {
            DexClass[] classes = apkFile.getDexClasses();
            for (DexClass c : classes) {
                String classType = c.getClassType();
                String className = classType.trim();
                className = className.replace('/', '.');
                className = className.substring(1, className.length() - 1);

                dexClassNames.add(className);
            }
        } catch (IOException e) {
            System.out.println("[*] ERROR : Cannot get class names!");
        }

        return dexClassNames;
    }

    private static class Holder {
        private static final ApkParser instance = new ApkParser();
    }
}