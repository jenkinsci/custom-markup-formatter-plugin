package io.jenkins.plugins.formatter;

import com.google.common.base.Throwables;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.markup.MarkupFormatter;
import hudson.markup.MarkupFormatterDescriptor;
import org.kohsuke.stapler.DataBoundConstructor;
import org.owasp.html.HtmlSanitizer;
import org.owasp.html.HtmlStreamRenderer;
import org.owasp.html.PolicyFactory;

import java.io.IOException;
import java.io.Writer;
import java.lang.reflect.InvocationTargetException;

public class CustomMarkupFormatter extends MarkupFormatter {

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
                Throwables::propagate, // System.out suppresses IOExceptions
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
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        } catch (NoSuchMethodException e) {
            e.printStackTrace();
        } catch (InvocationTargetException e) {
            e.printStackTrace();
        } catch (DefinedException e) {
            e.printStackTrace();
        }

        if(DEFINITION == null) {
            try {
                DEFINITION = CustomPolicyBuilder.build(PolicyConfiguration.DEFAULT_POLICY);
                HtmlSanitizer.sanitize(s, DEFINITION.apply(renderer));
            } catch (IllegalAccessException e) {
                e.printStackTrace();
            } catch (NoSuchMethodException e) {
                e.printStackTrace();
            } catch (InvocationTargetException e) {
                e.printStackTrace();
            } catch (DefinedException e) {
                e.printStackTrace();
            }
        }



    }

    @Extension
    public static class DescriptorImpl extends MarkupFormatterDescriptor {
        @Override
        public String getDisplayName() {
            return "Customizable HTML Formatter";
        }
    }

    public static final MarkupFormatter INSTANCE = new CustomMarkupFormatter(false);
}
