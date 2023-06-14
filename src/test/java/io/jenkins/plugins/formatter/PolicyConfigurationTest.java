package io.jenkins.plugins.formatter;

import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlTextArea;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Rule;
import org.jvnet.hudson.test.RestartableJenkinsRule;

public class PolicyConfigurationTest {

    @Rule
    public RestartableJenkinsRule rr = new RestartableJenkinsRule();

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
    public void uiAndStorage() {
        rr.then(r -> {
            assertNotNull("Have a default Policy", PolicyConfiguration.get().getPolicyDefinition());
            HtmlForm config = r.createWebClient().goTo("configure").getFormByName("config");
            HtmlTextArea textarea = config.getTextAreaByName("_.policyDefinition");
            textarea.setText("[{\"type\":\"default\", \"name\":\"2\"}]");
            r.submit(config);
            assertEquals("global config page let us edit it", "[{\"type\":\"default\", \"name\":\"2\"}]", PolicyConfiguration.get().getPolicyDefinition());
        });
        rr.then(r -> {
            assertEquals("still there after restart of Jenkins", "[{\"type\":\"default\", \"name\":\"2\"}]", PolicyConfiguration.get().getPolicyDefinition());
        });
    }

}
