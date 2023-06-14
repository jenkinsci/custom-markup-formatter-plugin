package io.jenkins.plugins.formatter;

import org.json.JSONArray;
import org.json.JSONObject;
import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.PolicyFactory;
import org.owasp.html.Sanitizers;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.regex.Pattern;

public class CustomPolicyBuilder {

    public static final String INBUILT_TYPE = "inbuilt";
    public static final String NEW_TYPE = "new";
    public static final String DEFAULT_TYPE = "default";

    public static void trimArray(String[] arr) {
        for(int i = 0; i < arr.length; i++) { arr[i] = arr[i].trim(); }
    }

    private static PolicyFactory getInbuiltPolicy(String name) throws DefinedException {
        name = name.toUpperCase().trim();
        switch (name) {
            case "BLOCKS":
                return Sanitizers.BLOCKS;
            case "TABLES":
                return Sanitizers.TABLES;
            case "LINKS":
                return Sanitizers.LINKS;
            case "FORMATTING":
                return Sanitizers.FORMATTING;
            case "IMAGES":
                return Sanitizers.IMAGES;
            case "STYLES":
                return Sanitizers.STYLES;
            default:
                throw new DefinedException("No inbuilt policy named \"" + name + "\" found");
        }
    }

    public static PolicyFactory build(String jsonArrayString) throws IllegalAccessException, NoSuchMethodException, InvocationTargetException, DefinedException {
        JSONArray policyJsonArray = new JSONArray(jsonArrayString);
        PolicyFactory policyFactory = parseJsonPolicy(policyJsonArray.getJSONObject(0));
        for(int policyNumber = 1; policyNumber < policyJsonArray.length(); policyNumber++) {
            JSONObject policyJson = policyJsonArray.getJSONObject(policyNumber);
            PolicyFactory policy = parseJsonPolicy(policyJson);
            policyFactory = policyFactory.and(policy);
        }
        return policyFactory;
    }

    public static PolicyFactory parseJsonPolicy(JSONObject policyJson) throws InvocationTargetException, IllegalAccessException, NoSuchMethodException, DefinedException {
        String type = policyJson.getString("type");

        switch (type) {
            case INBUILT_TYPE:
                String[] inbuiltPolicyNames = policyJson.getString("name").split(",");
                PolicyFactory policyFactory = getInbuiltPolicy(inbuiltPolicyNames[0]);
                for(int inbuiltPolicyNumber = 1; inbuiltPolicyNumber < inbuiltPolicyNames.length; inbuiltPolicyNumber++) {
                    policyFactory = policyFactory.and(getInbuiltPolicy(inbuiltPolicyNames[inbuiltPolicyNumber]));
                }
                return policyFactory;
            case NEW_TYPE:
                HtmlPolicyBuilder policyBuilder = new HtmlPolicyBuilder();
                if(policyJson.has("allow")) {
                    JSONObject allowedTags = policyJson.getJSONObject("allow");
                    for(String tagListStr : allowedTags.keySet()) {
                        String[] tagList = tagListStr.split(",");
                        Object tagAttrConfigValue = allowedTags.get(tagListStr);
                        JSONArray attrConfigList = new JSONArray();
                        if(tagAttrConfigValue instanceof String) {
                            String[] attributeList = allowedTags.getString(tagListStr).split(",");
                            trimArray(attributeList);
                            for(String attr: attributeList) {
                                String[] a = attr.split("::", 2);
                                JSONObject jsonObject = new JSONObject();
                                jsonObject.put("name", a[0]);
                                if(a.length > 1) {
                                    jsonObject.put("pattern", a[1]);
                                }
                                attrConfigList.put(jsonObject);
                            }
                        }
                        else if(tagAttrConfigValue instanceof JSONArray) {
                            JSONArray attrJSONArrayList = (JSONArray) tagAttrConfigValue;
                            for(int i = 0; i < attrJSONArrayList.length(); i++) {
                                Object attr = attrJSONArrayList.get(i);
                                if(attr instanceof String) {
                                    String[] a = ((String) attr).trim().split("::", 2);
                                    JSONObject jsonObject = new JSONObject();
                                    jsonObject.put("name", a[0]);
                                    if(a.length > 1) {
                                        jsonObject.put("pattern", a[1]);
                                    }
                                    attrConfigList.put(jsonObject);
                                }
                                else if(attr instanceof JSONObject) {
                                    attrConfigList.put(attr);
                                }
                                else {
                                    throw new DefinedException("Invalid value " + attrJSONArrayList.getString(i));
                                }
                            }
                        }
                        else {
                            throw new DefinedException("Invalid value for tag: " + tagListStr);
                        }

                        trimArray(tagList);
                        for(String tag : tagList) {
                            policyBuilder = policyBuilder.allowElements(tag);
                            if(attrConfigList.length() > 0) {
                                policyBuilder = policyBuilder.allowWithoutAttributes(tag);
                                for(int attrNum = 0; attrNum < attrConfigList.length(); attrNum++) {
                                    JSONObject attrConfig = attrConfigList.getJSONObject(attrNum);
                                    if(attrConfig.has("pattern")) {
                                        Pattern pattern = Pattern.compile(attrConfig.getString("pattern"));
                                        policyBuilder = policyBuilder.allowAttributes(attrConfig.getString("name"))
                                                .matching(pattern).onElements(tag);
                                    }
                                    else {
                                        policyBuilder = policyBuilder.allowAttributes(attrConfig.getString("name"))
                                                .onElements(tag);
                                    }
                                }
                            }
                        }
                    }
                }
                if(policyJson.has("methods")) {
                    JSONObject methods = policyJson.getJSONObject("methods");
                    for(String methodName : methods.keySet()) {
                        String[] args = methods.getString(methodName).split(",");

                        trimArray(args);
                        Method method;
                        if(args[0].equals("")) {
                            method = policyBuilder.getClass().getMethod(methodName);
                        }
                        else {
                            method = policyBuilder.getClass().getMethod(methodName, String[].class);

                        }
                        Class returnType = method.getReturnType();

                        if(returnType == HtmlPolicyBuilder.class && args[0].equals("")) {
                            policyBuilder = (HtmlPolicyBuilder) method.invoke(policyBuilder);
                        }
                        else if(returnType == HtmlPolicyBuilder.class) {
                            policyBuilder = (HtmlPolicyBuilder) method.invoke(policyBuilder, new Object[] {args});
                        }
                        else if(returnType == HtmlPolicyBuilder.AttributeBuilder.class) {
                            String tagName = policyJson.getString("name");
                            HtmlPolicyBuilder.AttributeBuilder attrPolicy = (HtmlPolicyBuilder.AttributeBuilder) method.invoke(policyBuilder, new Object[] {args});
                            policyBuilder = attrPolicy.onElements(tagName);
                        }
                    }
                }

                return policyBuilder.toFactory();

            case DEFAULT_TYPE:
                String name = policyJson.getString("name");
                if(name.equals("1")) {
                    String defaultJsonPolicy = "[\n" +
                            "\t{\n" +
                            "\t\t\"type\": \"inbuilt\",\n" +
                            "\t\t\"name\": \"blocks, formatting, styles, tables, images\"\n" +
                            "\t},\n" +
                            "\t{\n" +
                            "\t\t\"type\": \"new\",\n" +
                            "\t\t\"allow\": {\n" +
                            "\t\t\t\"dl, dt, dd, hr, pre\": \"\",\n" +
                            "\t\t\t\"font\": \"size, color\",\n" +
                            "\t\t\t\"a\": \"href, target\"\n" +
                            "\t\t},\n" +
                            "\t\t\"methods\": {\n" +
                            "\t\t\t\"allowStandardUrlProtocols\": \"\"\n" +
                            "\t\t}\n" +
                            "\t}\n" +
                            "]";
                    return CustomPolicyBuilder.build(defaultJsonPolicy);
                }
                else if(name.equals("2")) {
                    String defaultJsonPolicy = "[\n" +
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
                    return CustomPolicyBuilder.build(defaultJsonPolicy);
                }
                throw new DefinedException("No such Default policy found");
            default:
                return null;
        }
    }

    public static final PolicyFactory ADDITIONS = new HtmlPolicyBuilder().allowElements("dl", "dt", "dd", "hr", "pre")
            .allowElements("font").allowWithoutAttributes("font")
            .allowAttributes("size", "color").onElements("font")
            .allowStandardUrlProtocols().allowElements("a")
            .allowAttributes("href", "target").onElements("a")
            .toFactory();

    public static void main(String[] args) {
        String jsonString = "[\n" +
                "\t{\n" +
                "\t\t\"type\": \"inbuilt\",\n" +
                "\t\t\"name\": \"blocks, formatting, blocks, tables, images\"\n" +
                "\t},\n" +
                "\t{\n" +
                "\t\t\"type\": \"new\",\n" +
                "\t\t\"methods\": {\n" +
                "\t\t\t\"allowElements\": \"dl, dt, dd, hr, pre\"\n" +
                "\t\t}\n" +
                "\t},\n" +
                "\t{\n" +
                "\t\t\"type\": \"new\",\n" +
                "\t\t\"name\": \"font\",\n" +
                "\t\t\"methods\": {\n" +
                "\t\t\t\"allowElements\": \"font\",\n" +
                "\t\t\t\"allowWithoutAttributes\": \"font\",\n" +
                "\t\t\t\"allowAttributes\": \"size, color\"\n" +
                "\t\t}\n" +
                "\t},\n" +
                "\t{\n" +
                "\t\t\"type\": \"new\",\n" +
                "\t\t\"name\": \"a\",\n" +
                "\t\t\"methods\": {\n" +
                "\t\t\t\"allowStandardUrlProtocols\": \"\",\n" +
                "\t\t\t\"allowElements\": \"a\",\n" +
                "\t\t\t\"allowAttributes\": \"href, target\"\n" +
                "\t\t}\n" +
                "\t}\n" +
                "]";

        String htmlString = "<font color=\"red\" size = \"5\"> hello";

        PolicyFactory policyFactory = null;
        try {
            policyFactory = build(jsonString);
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        } catch (NoSuchMethodException e) {
            e.printStackTrace();
        } catch (InvocationTargetException e) {
            e.printStackTrace();
        } catch (DefinedException e) {
            e.printStackTrace();
        }
        System.out.println(policyFactory.sanitize(htmlString));

    }
}
