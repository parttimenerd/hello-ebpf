package me.bechberger.ebpf.gen;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import me.bechberger.ebpf.gen.Generator.Type.FuncType;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Processes a JSON file containing the bpf helper functions and their descriptions and outputs the class BPFHelpers
 * that contains all the helper functions as static methods.
 * <p>
 * The file is provided by Dylan Reimerink and based on <a href="https://ebpf-docs.dylanreimerink.nl/">ebpf-docs</a>
 * <p>
 * Expected format of the file:
 * <code>
 * {
 * "helper name": {
 * "Name": "helper name",
 * "Definition": "function variable declaration in C",
 * "Description": "description in markdown"
 * },
 * ...
 * }
 * </code>
 */
public class HelperJSONProcessor {

    private static final String CLASS_NAME = "BPFHelpers";

    private final Generator generator;
    private final org.commonmark.parser.Parser markdownParser = org.commonmark.parser.Parser.builder().build();
    private final org.commonmark.renderer.html.HtmlRenderer htmlRenderer =
            org.commonmark.renderer.html.HtmlRenderer.builder().build();

    public HelperJSONProcessor(String basePackage) {
        generator = new Generator(basePackage);
    }

    public void process(Path jsonFile) {
        try {
            process(JSON.parseObject(Files.readString(jsonFile)));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private void process(JSONObject types) {
        types.values().stream().map(e -> processHelperObject((JSONObject) e)).forEach(generator::addAdditionalType);
    }

    private FuncType processHelperObject(JSONObject helperObject) {
        if (!helperObject.keySet().equals(Set.of("Name", "Definition", "Description"))) {
            throw new RuntimeException("Unexpected JSON format, expected object to only contain the keys 'Name', " +
                    "'Definition', and 'Description', not " + helperObject.keySet());
        }
        var name = helperObject.getString("Name");
        var definition = helperObject.getString("Definition");
        var description = helperObject.getString("Description");
        var funcType = DeclarationParser.parseFunctionVariableDeclaration(definition);
        if (!name.equals(funcType.name())) {
            throw new RuntimeException("Name in JSON does not match name in definition: " + name + " != " + funcType.name());
        }
        return funcType.setJavaDoc(descriptionToJavaDoc(description));
    }

    record DescriptionParts(String mainDescription, String returnDescription) {
    }

    /**
     * Splits the description into the main description and the return description
     * <p>
     * The main part is everything after the first line, indented via tabs, till the line "Returns"
     * The return part the part after "Returns" till the end
     */
    private DescriptionParts splitDescription(String description) {
        var lines = description.lines().iterator();
        List<String> mainDescription = new ArrayList<>();
        List<String> returnDescription = new ArrayList<>();
        lines.next(); // skip the first line
        while (lines.hasNext()) {
            var line = lines.next();
            if (line.equals(" Returns")) {
                break;
            }
            if (line.startsWith(" \t")) {
                mainDescription.add(line.substring(2));
            } else {
                mainDescription.add(line);
            }
        }
        while (lines.hasNext()) {
            var line = lines.next();
            if (line.startsWith(" \t")) {
                returnDescription.add(line.substring(2));
            } else {
                returnDescription.add(line);
            }
        }
        return new DescriptionParts(String.join("\n", mainDescription), String.join("\n", returnDescription));
    }

    private String descriptionToJavaDoc(String description) {
        var parts = splitDescription(description);
        return markdownToHTML(parts.mainDescription) + "\n" + "@return " + markdownToHTML(parts.returnDescription);
    }

    private String markdownToHTML(String markdown) {
        var html = htmlRenderer.render(markdownParser.parse(markdown)).strip();
        if (html.startsWith("<p>") && html.endsWith("</p>")) {
            return html.substring(3, html.length() - 4);
        }
        return html;
    }

    /**
     * Store the generated Java file in the package in the given folder
     */
    public void storeInFolder(Path outputDirectory) {
        generator.storeInFolder(outputDirectory, CLASS_NAME, "BPF helper functions");
    }
}
