package me.bechberger.ebpf.gen;

/**
 * Converts markdown to HTML
 */
public class Markdown {
    private final org.commonmark.parser.Parser markdownParser = org.commonmark.parser.Parser.builder().build();
    private final org.commonmark.renderer.html.HtmlRenderer htmlRenderer =
            org.commonmark.renderer.html.HtmlRenderer.builder().build();

    public String markdownToHTML(String markdown) {
        var html = htmlRenderer.render(markdownParser.parse(markdown)).strip();
        if (html.startsWith("<p>") && html.endsWith("</p>")) {
            return html.substring(3, html.length() - 4);
        }
        return html;
    }
}
