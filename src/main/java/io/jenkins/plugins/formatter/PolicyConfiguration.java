package io.jenkins.plugins.formatter;

import hudson.Extension;
import hudson.util.FormValidation;
import jenkins.model.GlobalConfiguration;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Example of Jenkins global configuration.
 */
@Extension
public class PolicyConfiguration extends GlobalConfiguration {

    private static final Logger LOGGER = Logger.getLogger(PolicyConfiguration.class.getName());

    /**
     * @return the singleton instance
     */
    public static PolicyConfiguration get() {
        return GlobalConfiguration.all().get(PolicyConfiguration.class);
    }

    private String policyDefinition;

    public static final String DEFAULT_POLICY = """
            [
                {
                    "type": "inbuilt",
                    "name": "blocks, formatting, styles, links, tables, images"
                },
                {
                    "type": "new",
                    "allow": {
                        "dl, dt, dd, hr, pre": ""
                    }
                }
            ]""";

    public PolicyConfiguration() {
        // When Jenkins is restarted, load any saved configuration from disk.
        load();
        if (getPolicyDefinition() == null || getPolicyDefinition().isEmpty()) {
            setPolicyDefinition(DEFAULT_POLICY);
        }
    }

    /**
     * @return the currently configured label, if any
     */
    public String getPolicyDefinition() {
        return policyDefinition;
    }

    /**
     * Together with {@link #getPolicyDefinition}, binds to entry in {@code config.jelly}.
     *
     * @param policyDefinition the new value of this field
     */
    @DataBoundSetter
    public void setPolicyDefinition(String policyDefinition) {
        this.policyDefinition = policyDefinition;
        save();
    }

    @SuppressWarnings({"lgtm[jenkins/no-permission-check]", "lgtm[jenkins/csrf]"})
    public FormValidation doCheckPolicyDefinition(@QueryParameter String value) {
        if (StringUtils.isEmpty(value)) {
            return FormValidation.warning("Please specify a value.");
        }

        try {
            CustomPolicyBuilder.build(value);
        } catch (NoSuchMethodException e) {
            LOGGER.log(Level.WARNING, "Unable to build custom policy definition", e);
            return FormValidation.error("No such method " + e.getMessage());
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Unable to build custom policy definition", e);
            return FormValidation.error(e.getMessage());
        }

        return FormValidation.ok();
    }

}
