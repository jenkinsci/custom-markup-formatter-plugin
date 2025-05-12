package io.jenkins.plugins.formatter;

import org.htmlunit.html.HtmlForm;
import org.htmlunit.html.HtmlTextArea;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@WithJenkins
class PolicyConfigurationTest {

    private JenkinsRule r;

    @BeforeEach
    void setUp(JenkinsRule rule) {
        r = rule;
    }

    /**
     * Tries to exercise enough code paths to catch common mistakes:
     * <ul>
     * <li>missing {@code load}
     * <li>missing {@code save}
     * <li>misnamed or absent getter/setter
     * <li>misnamed {@code textbox}
     * </ul>
     */
    @Test
    void uiAndStorage() throws Throwable {
        assertNotNull(PolicyConfiguration.get().getPolicyDefinition(), "Have a default Policy");
        HtmlForm config = r.createWebClient().goTo("configure").getFormByName("config");
        HtmlTextArea textarea = config.getTextAreaByName("_.policyDefinition");
        textarea.setText("[{\"type\":\"default\", \"name\":\"2\"}]");
        r.submit(config);
        assertEquals("[{\"type\":\"default\", \"name\":\"2\"}]", PolicyConfiguration.get().getPolicyDefinition(), "global config page let us edit it");

        r.restart();

        assertEquals("[{\"type\":\"default\", \"name\":\"2\"}]", PolicyConfiguration.get().getPolicyDefinition(), "still there after restart of Jenkins");
    }

}
