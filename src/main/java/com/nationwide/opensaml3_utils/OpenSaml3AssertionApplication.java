package com.nationwide.opensaml3_utils;

import java.io.File;
import java.net.URL;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;

import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.saml.saml2.core.Response;
import org.w3c.dom.Element;

public class OpenSaml3AssertionApplication {

	static {
		// load libraries/dependencies
		loadDepdencies();
	}

	private static void loadDepdencies() {
		try {
			// Initialize Open SAML V3 libraries
			InitializationService.initialize();
		} catch (InitializationException e) {
			System.err
					.println("OpenSaml3AssertionApplication: Unable to load/initialize OpenSAML v3 libraries....." + e);
			e.printStackTrace();
		}
	}

	public Map<String, String> buildSAMLAssertionObjects(String jksFilePath, String jksKeystorePassword,
			String keyPassword, String certAlias, String issuerID, String entityID, String audienceRestrictionURL,
			String samlAuthnCtxClassRef, int assertionTimeoutInMin) throws Exception {
		String jksFileAbsPath = null;
		File jksFile = new File(jksFilePath);
		if (jksFile == null || !jksFile.exists()) {
			System.out.println("SystemClassLoader is going to load JKS File =" + jksFilePath);
			// returns the ClassLoader object associated with System
			ClassLoader classLoader = ClassLoader.getSystemClassLoader();
			jksFile = new File(classLoader.getResource(jksFilePath).getFile());
			if (jksFile == null || !jksFile.exists()) {
				System.out.println("ClassLoader is going to load JKS File =" + jksFilePath);
				// finds resource
				URL url = ClassLoader.getSystemResource(jksFilePath);
				jksFile = new File(url.toExternalForm());
			}
		}

		jksFileAbsPath = jksFile.getAbsolutePath();
		System.out.println("JKS File Absolute Path=" + jksFileAbsPath);

		return buildSAMLAssertionObjects(jksFile, jksKeystorePassword, keyPassword, certAlias, issuerID, entityID,
				audienceRestrictionURL, samlAuthnCtxClassRef, assertionTimeoutInMin);
	}

	public Map<String, String> buildSAMLAssertionObjects(File jksFile, String jksKeystorePassword, String keyPassword,
			String certAlias, String issuerID, String entityID, String audienceRestrictionURL,
			String samlAuthnCtxClassRef, int assertionTimeoutInMin) throws Exception {
		Map<String, String> samlMap = new HashMap<String, String>();

		int defaultAssertionTimeoutInMin = 60;
		if (assertionTimeoutInMin < defaultAssertionTimeoutInMin) {
			assertionTimeoutInMin = defaultAssertionTimeoutInMin;
		}

		// build SAML Response
		Response samlResponse = OpenSaml3Utils.buildSAMLResponse(jksFile, jksKeystorePassword, keyPassword, certAlias,
				issuerID, entityID, audienceRestrictionURL, samlAuthnCtxClassRef, assertionTimeoutInMin);

		// Marshall (Java Object to XML Object) SAMLResponse into Element
		Element samlResponseElm = OpenSaml3Utils.marshallSAMLResponse(samlResponse);

		// get Pretty Print
		String samlResponseStr = OpenSaml3Utils.getSAMLAssertionInPrettyPrint(samlResponseElm);

		// fetch SAMLAssertion from SAMLResponse
		String samlAssertionStr = OpenSaml3Utils.fetchSAMLAssertionFrom(samlResponseStr);

		// encode the SAML assertion
		String samlAssertionEncoded = OpenSaml3Utils.base64EncodeSAML(samlAssertionStr);

		// Important to URLEncode to avoid any termination of SAML data over HTTP
		// Reason: Base64 encoded strings can contain the + character. If the +
		// character is placed on a URL query parameter, it is interpreted as a space
		// during transfer over HTTP
		String samlAssertionURLEncoded = URLEncoder.encode(samlAssertionEncoded, "UTF-8");

		samlMap.put("SAML_RESPONSE", samlResponseStr);
		samlMap.put("SAML_ASSERTION", samlAssertionStr);
		samlMap.put("SAML_ASSERTION_BASE64_ENCODED", samlAssertionEncoded);
		samlMap.put("SAML_ASSERTION_URLENCODED_BASE64", samlAssertionURLEncoded);

		return samlMap;
	}
}
