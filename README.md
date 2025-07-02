# custom-markup-formatter

## Introduction

This is a customizable HTML Markup Formatter used to sanitize the HTML content.

This project is based upon [OWASP Java HTML Sanitizer](https://github.com/OWASP/java-html-sanitizer).

## Getting started

#### Setting the formatter

1. Navigate to *Configure Global Security page*

    (Jenkins Home page -> Manage Jenkins -> Configure Global Security)
2. Navigate to *Markup Formatter* parameter and select *Customizable HTML Formatter* from the dropdown menu

#### Customizing the formatter

- Change the *Policy* parameter under *Customizable HTML Formatter Plugin* in the *Configure System* page

    (Jenkins Home page -> Manage Jenkins -> Configure System)
    
- The format of the policy is simple and you can get started by directly seeing the default definition shown in **Default policies** section.
    
## Define Custom Policy

- The resultant policy is defined as a combination of different policies represented as JSON array.
Thus, each element in the JSON array represents one policy.

    ```json
    [
      {
        "policy 1": "definition"
      },
      {
        "policy 2": "definition"
      }
    ]
    ```
  
    **Note:** The policy defined does not depend on indentation as long as it is a valid JSON. However, the parameters and values are case-sensitive unless explicitly mentioned. 

- There are different types of policy you can define as shown below.
    1. **Default Policy**
        ```json
        {
          "type": "default",
          "name": "<DEFAULT_NUMBER>"
        }
        ```
        Define the value of **_DEFAULT_NUMBER_** from the available default policies packaged with the plugin as defined [here](#Default-Policies).
    
    2. **Inbuilt Policy**
    
        Inbuilt policy is defined in the Sanitizers class available at [[GitHub](https://github.com/OWASP/java-html-sanitizer/blob/main/owasp-java-html-sanitizer/src/main/java/org/owasp/html/Sanitizers.java), [DOCS](https://www.javadoc.io/doc/com.googlecode.owasp-java-html-sanitizer/owasp-java-html-sanitizer/latest/org/owasp/html/Sanitizers.html)].
        ```json
        {
         "type": "inbuilt",
         "name": "<INBUILT_POLICY_NAME>"
        }
        ``` 
        **_INBUILT_POLICY_NAME_** can be a comma seperated list such as _"blocks, links"_ or as individual _"links"_
        
        Supported values are: BLOCKS, LINKS, FORMATTING, IMAGES, STYLES, TABLES
        
        **Note:** Value of _INBUILT_POLICY_NAME_ is not case-sensitive and does not depend on extra spaces.("     blOCks,        Links" is same as "blocks, links")
         
    3. **New Policy**
        
        ```json
        {
         "type": "new",
         "name": "<TAG_NAME> <OPTIONAL: Only required if using methods allowAttributes and disallowAttributes>",
         "allow": {
           "<TAG_LIST1 Comma-seperated>": "<ATTRIBUTE_LIST Comma-seperated>",
           "<TAG_LIST2 Comma-seperated>": "<ATTRIBUTE_LIST Comma-seperated>"
         },
         "methods": {
           "<METHOD1>": "<Comma-seperated parameters>",
           "<METHOD2>": "<Comma-seperated parameters>"
         }
        }
        ```     
       
       In most cases, only using **allow** will do the job. **methods** can be used for more advanced configuration. The list of methods are part of HtmlPolicyBuilder available at [[GitHub](https://github.com/OWASP/java-html-sanitizer/blob/main/owasp-java-html-sanitizer/src/main/java/org/owasp/html/HtmlPolicyBuilder.java), [DOCS](https://www.javadoc.io/doc/com.googlecode.owasp-java-html-sanitizer/owasp-java-html-sanitizer/latest/org/owasp/html/HtmlPolicyBuilder.html)]
       
       **Note:** Supports method with String parameters or no parametes and return type as being HtmlPolicyBuilder and AttributeBuilder as defined in the docs.

## Default Policies

The value or name of default policies are numbers. Currently, there are two default policies with this plugin.

1. Policy 1
    ```json
    [
        {
            "type": "inbuilt",
            "name": "blocks, formatting, blocks, tables, images"
        },
        {
        	"type": "new",
        	"allow": {
                "dl, dt, dd, hr, pre": "",
                "font": "size, color",
                "a": "href, target"
        	},
            "methods": {
                "allowStandardUrlProtocols": ""
            }
        }
    ]
    ``` 
    This is same as 
    ```json
    [
      {
        "type": "default",
        "name": "1"
      }
    ]
    ```

2. Policy 2

    ```json
    [
       {
     	"type": "inbuilt",
     	"name": "blocks, formatting, blocks, links, tables, images"
       },
       {
     	"type": "new",
     	"allow": {
        	    "dl, dt, dd, hr, pre": ""
        }
       }     
    ]
    ```
