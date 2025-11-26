# opensaml3-utils
A Java utility built on OpenSAML3 libraries to generate SAML objects such as Response and Assertion.
 
Learn about **Prerequisites** (Certificate, PrivateKey, Java KeyStore etc.) of this utility at [opensaml3-utils-usage](https://github.nwie.net/Nationwide/opensaml3-utils/blob/master/opensaml3-utils-usage.docx) or [saml-assertion-generation](https://github.nwie.net/Nationwide/opensaml3-utils/blob/master/saml-assertion-generation.docx).

### Usage in local developer machine: 
Run the following commands in your developer machine, assuming Git and Maven have been installed and configured.

1. git clone https://github.nwie.net/Nationwide/opensaml3-utils.git
2. cd opensaml3-utils
3. mvn clean
4. mvn install

### Run:
*Run either **one** of the following to see the output.*

1. With **default inputs**, Run main() method of "OpenSaml3AssertionAppTest.java" class. A Test certificate and a JKS is shipped with test suite.
2. With **custom inputs**, invoke *Map<String, String> **buildSAMLAssertionObjects**(String jksFilePath, String jksKeystorePassword, String keyPassword, String certAlias, String issuerID, String entityID, String audienceRestrictionURL, String samlAuthType, int assertionTimeoutInMin)* on the instance of *OpenSaml3AssertionApplication*.
3. With **custom inputs**, invoke *Map<String, String> **buildSAMLAssertionObjects**(File jksFile, String jksKeystorePassword, String keyPassword, String certAlias, String issuerID, String entityID, String audienceRestrictionURL, String samlAuthType, int assertionTimeoutInMin)* on the instance of *OpenSaml3AssertionApplication*

### Output:
A Java.util.Map is returned with following four key-value pairs.

1. *SAML_RESPONSE* = A xml-string representation of SAMLResponse.
2. *SAML_ASSERTION* = A xml-string representation of SAMLAssertion extracted from value of "SAML_RESPONSE" object.
3. *SAML_ASSERTION_BASE64_ENCODED* = A Base64 Encoded value of "SAML_ASSERTION" object.
4. *SAML_ASSERTION_URLENCODED_BASE64* = A URL Encoded value of "SAML_ASSERTION_BASE64_ENCODED" object.

*Note:* The most desired Base64Encoded of <Saml:Assertion/> is associated with "SAML_ASSERTION_BASE64_ENCODED" key in the map.

### Publish maven artificat (JAR) file to Nexus:
mvn deploy:deploy-file -DgroupId=com.nationwide -DartifactId=opensaml3-utils -Dversion=0.0.1 -Dpackaging=jar -Dfile=opensaml3-utils-0.0.1.jar -DrepositoryId=releases -Durl=http://repo.nwie.net/nexus/content/repositories/maven-internal/

### Publish maven artificat (JAR) file to Artifactory:
mvn deploy
