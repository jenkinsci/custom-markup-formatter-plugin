package io.jenkins.plugins.formatter;

import hudson.Extension;
import hudson.util.FormValidation;
import jenkins.model.GlobalConfiguration;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;
import org.owasp.html.PolicyFactory;

import java.lang.reflect.InvocationTargetException;

/**
 * Example of Jenkins global configuration.
 */
@Extension
public class PolicyConfiguration extends GlobalConfiguration {

    /** @return the singleton instance */
    public static PolicyConfiguration get() {
        return GlobalConfiguration.all().get(PolicyConfiguration.class);
    }

    private String policyDefinition;

    public static final String DEFAULT_POLICY = "[\n" +
            "\t{\n" +
            "\t\t\"type\": \"inbuilt\",\n" +
            "\t\t\"name\": \"blocks, formatting, styles, links, tables, images\"\n" +
            "\t},\n" +
            "\t{\n" +
            "\t\t\"type\": \"new\",\n" +
            "\t\t\"allow\": {\n" +
            "\t\t\t\"dl, dt, dd, hr, pre\": \"\"\n" +
            "\t\t}\n" +
            "\t}\n" +
            "]";

    public PolicyConfiguration() {
        // When Jenkins is restarted, load any saved configuration from disk.
        load();
        if(getPolicyDefinition() == null || getPolicyDefinition().equals("")) {
            setPolicyDefinition(DEFAULT_POLICY);
        }
    }

    /** @return the currently configured label, if any */
    public String getPolicyDefinition() {
        return policyDefinition;
    }

    /**
     * Together with {@link #getPolicyDefinition}, binds to entry in {@code config.jelly}.
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
        } catch (IllegalAccessException e) {
            e.printStackTrace();
            return FormValidation.error(e.getMessage());
        } catch (NoSuchMethodException e) {
            e.printStackTrace();
            return FormValidation.error("No such method " + e.getMessage());
        } catch (InvocationTargetException e) {
            e.printStackTrace();
            return FormValidation.error(e.getMessage());
        } catch (DefinedException e) {
            e.printStackTrace();
            return FormValidation.error(e.getMessage());
        } catch (Exception e) {
            e.printStackTrace();
            return FormValidation.error(e.getMessage());
        }

        return FormValidation.ok();
    }

}
