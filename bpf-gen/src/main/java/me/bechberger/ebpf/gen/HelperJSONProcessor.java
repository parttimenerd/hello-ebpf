package me.bechberger.ebpf.gen;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import me.bechberger.ebpf.gen.Generator.GeneratorConfig;
import me.bechberger.ebpf.gen.Generator.NameTranslator;
import me.bechberger.ebpf.gen.Generator.Type.FuncType;
import me.bechberger.ebpf.gen.Generator.TypeJavaFiles;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
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
    private final NameTranslator translator;
    private final Markdown markdown = new Markdown();


    public HelperJSONProcessor(String basePackage, NameTranslator translator) {
        generator = new Generator(basePackage);
        this.translator = translator;
    }

    public HelperJSONProcessor(String basePackage) {
        this(basePackage, new NameTranslator(new Generator("")));
    }

    public void process(Path jsonFile) {
        try {
            process(JSON.parseObject(Files.readString(jsonFile)));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private void process(JSONObject types) {
        types.values().stream().map(e -> processHelperObject((JSONObject) e)).sorted(Comparator.comparing(FuncType::name)).forEach(generator::addAdditionalType);
    }

    private FuncType processHelperObject(JSONObject helperObject) {
        if (!helperObject.keySet().equals(Set.of("Name", "Definition", "Description"))) {
            throw new RuntimeException("Unexpected JSON format, expected object to only contain the keys 'Name', " +
                    "'Definition', and 'Description', not " + helperObject.keySet());
        }
        var name = helperObject.getString("Name");
        var definition = helperObject.getString("Definition");
        var description = helperObject.getString("Description");
        var funcType = DeclarationParser.parseFunctionVariableDeclaration(translator, definition);
        if (!name.equals(funcType.name())) {
            throw new RuntimeException("Name in JSON does not match name in definition: " + name + " != " + funcType.name());
        }
        return funcType.setJavaDoc(descriptionToJavaDoc(description, !funcType.impl().returnsVoid()));
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

    private String descriptionToJavaDoc(String description, boolean withReturn) {
        var parts = splitDescription(description);
        return markdown.markdownToHTML(parts.mainDescription) + (withReturn ?
                "\n" + "@return " + markdown.markdownToHTML(parts.returnDescription) : "");
    }

    /**
     * Store the generated Java file in the package in the given folder
     */
    TypeJavaFiles createClass(TypeJavaFiles generated) {
        return generator.generateJavaFiles(new GeneratorConfig("BPFHelpers") {
            @Override
            public String classDescription() {
                return "BPF helper functions, based on <a href=\"https://ebpf-docs.dylanreimerink" +
                        ".nl/linux/helper-function/\">ebpf-docs</a>";
            }

            @Override
            public List<String> additionalImports() {
                return generated.generateStaticImportsForAll();
            }
        });
    }
}