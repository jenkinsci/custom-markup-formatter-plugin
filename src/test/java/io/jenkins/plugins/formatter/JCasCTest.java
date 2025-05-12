package io.jenkins.plugins.formatter;

import hudson.markup.MarkupFormatter;
import io.jenkins.plugins.casc.misc.junit.jupiter.AbstractRoundTripTest;
import jenkins.model.Jenkins;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;


@WithJenkins
class JCasCTest extends AbstractRoundTripTest {

    @Override
    protected void assertConfiguredAsExpected(JenkinsRule j, String configContent) {
        MarkupFormatter formatter = Jenkins.get().getMarkupFormatter();
        CustomMarkupFormatter customMarkupFormatter = assertInstanceOf(CustomMarkupFormatter.class, formatter);
        assertTrue(customMarkupFormatter.disableSyntaxHighlighting);
    }

    @Override
    protected String stringInLogExpected() {
        return "Setting class " + CustomMarkupFormatter.class.getName() + ".disableSyntaxHighlighting = true";
    }
}
