package io.jenkins.plugins.formatter;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.markup.MarkupFormatter;
import hudson.markup.MarkupFormatterDescriptor;
import org.kohsuke.stapler.DataBoundConstructor;
import org.owasp.html.Handler;
import org.owasp.html.HtmlSanitizer;
import org.owasp.html.HtmlStreamRenderer;
import org.owasp.html.PolicyFactory;

import java.io.IOException;
import java.io.Writer;
import java.lang.reflect.InvocationTargetException;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CustomMarkupFormatter extends MarkupFormatter {

    private static final Logger LOGGER = Logger.getLogger(CustomMarkupFormatter.class.getName());

    final boolean disableSyntaxHighlighting;

    @DataBoundConstructor
    public CustomMarkupFormatter(final boolean disableSyntaxHighlighting) {
        this.disableSyntaxHighlighting = disableSyntaxHighlighting;
    }

    @Override
    public void translate(String s, @NonNull Writer writer) throws IOException {
        HtmlStreamRenderer renderer = HtmlStreamRenderer.create(
                writer,
                // Receives notifications on a failure to write to the output.
                Handler.PROPAGATE, // System.out suppresses IOExceptions
                // Our HTML parser is very lenient, but this receives notifications on
                // truly bizarre inputs.
                x -> {
                    throw new Error(x);
                }
        );

        PolicyFactory DEFINITION = null;
        try {
            DEFINITION = CustomPolicyBuilder.build(PolicyConfiguration.get().getPolicyDefinition());
            HtmlSanitizer.sanitize(s, DEFINITION.apply(renderer));
        } catch (IllegalAccessException | NoSuchMethodException | InvocationTargetException | DefinedException e) {
            LOGGER.log(Level.WARNING, "Unable to build custom policy definition", e);
        }

        if (DEFINITION == null) {
            try {
                DEFINITION = CustomPolicyBuilder.build(PolicyConfiguration.DEFAULT_POLICY);
                HtmlSanitizer.sanitize(s, DEFINITION.apply(renderer));
            } catch (IllegalAccessException | NoSuchMethodException | InvocationTargetException | DefinedException e) {
                LOGGER.log(Level.WARNING, "Unable to build default policy definition", e);
            }
        }
    }

    @Extension
    public static class DescriptorImpl extends MarkupFormatterDescriptor {
        @Override
        @NonNull
        public String getDisplayName() {
            return "Customizable HTML Formatter";
        }
    }

    public static final MarkupFormatter INSTANCE = new CustomMarkupFormatter(false);
}
