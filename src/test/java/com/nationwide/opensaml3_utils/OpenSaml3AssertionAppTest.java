package com.nationwide.opensaml3_utils;

import java.util.Map;

public class OpenSaml3AssertionAppTest {

	public static void main(String args[]) throws Exception {
		
		OpenSaml3AssertionAppTest openSaml3AssertionAppTest = new OpenSaml3AssertionAppTest();

		Map<String, String> samlMap = openSaml3AssertionAppTest.buildSAMLAssertionObjectsWithTestCertificate();

		System.out.println("OpenSaml3AssertionApplication.main(). SAML_RESPONSE=" + samlMap.get("SAML_RESPONSE"));
		System.out.println("OpenSaml3AssertionApplication.main(). SAML_ASSERTION=" + samlMap.get("SAML_ASSERTION"));
		System.out.println("OpenSaml3AssertionApplication.main(). SAML_ASSERTION_BASE64_ENCODED="
				+ samlMap.get("SAML_ASSERTION_BASE64_ENCODED"));
	}

	/**
	 * Build SAML Objects (Response, Assertion) with a TEST Certificate that
	 * Nationwide provided. <br/>
	 * 
	 * <b>WARNING:</b>: DO NOT USE THIS method in PRODUCTION env as it will fail due
	 * to invalid certificate configuration.
	 * 
	 * @return
	 * @throws Exception
	 */
	public Map<String, String> buildSAMLAssertionObjectsWithTestCertificate() throws Exception {
		String jksFilePath = "testcert/******NAME OF YOUR pfx FILE WHEN CERT CREATED*************";
		String jksKeystorePassword = "**********KEYSTORE PASSWORD**************";
		String keyPassword = "**********KEYSTORE PASSWORD**************";
		String certAlias = "**********CERT ALIAS**************";
		String issuerID = "**********ISSUER ID**************";
		String entityID = "********subject id**************";
		String audienceRestrictionURL = "https://identity-pt.nationwide.com";
		String samlAuthnCtxClassRef = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password";
		int samlAssertionTokenPeriodInMin = 60;

		OpenSaml3AssertionApplication openSaml3AssertionApp = new OpenSaml3AssertionApplication();
		Map<String, String> samlMap = openSaml3AssertionApp.buildSAMLAssertionObjects(jksFilePath, jksKeystorePassword,
				keyPassword, certAlias, issuerID, entityID, audienceRestrictionURL, samlAuthnCtxClassRef,
				samlAssertionTokenPeriodInMin);

		return samlMap;

	}
}