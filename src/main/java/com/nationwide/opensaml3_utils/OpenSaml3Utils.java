package com.nationwide.opensaml3_utils;

import java.io.File;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.UUID;

import org.joda.time.DateTime;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.common.SAMLObjectContentReference;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Audience;
import org.opensaml.saml.saml2.core.AudienceRestriction;
import org.opensaml.saml.saml2.core.AuthnContext;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.NameIDType;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml.saml2.core.impl.AssertionBuilder;
import org.opensaml.saml.saml2.core.impl.AudienceBuilder;
import org.opensaml.saml.saml2.core.impl.AudienceRestrictionBuilder;
import org.opensaml.saml.saml2.core.impl.AuthnContextBuilder;
import org.opensaml.saml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml.saml2.core.impl.AuthnStatementBuilder;
import org.opensaml.saml.saml2.core.impl.ConditionsBuilder;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml.saml2.core.impl.NameIDBuilder;
import org.opensaml.saml.saml2.core.impl.ResponseBuilder;
import org.opensaml.saml.saml2.core.impl.SubjectBuilder;
import org.opensaml.saml.saml2.core.impl.SubjectConfirmationBuilder;
import org.opensaml.saml.saml2.core.impl.SubjectConfirmationDataBuilder;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.security.x509.X509Credential;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.X509Data;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.Signer;
import org.w3c.dom.Element;

import net.shibboleth.utilities.java.support.xml.SerializeSupport;

public class OpenSaml3Utils {

	private static String SAML_METHOD = "urn:oasis:names:tc:SAML:2.0:cm:sender-vouches";

	public static String base64EncodeSAML(String saml) {
		String encodedSAMLString = Base64.getEncoder().encodeToString(saml.toString().getBytes());
		return encodedSAMLString;
	}

	public static Element marshallSAMLResponse(Response response) throws Exception {
		return XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(response).marshall(response);
	}

	public static Element marshallSAMLAssertion(Assertion assertion) throws Exception {
		return XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(assertion).marshall(assertion);
	}

	public static String getSAMLResponseInPrettyPrint(Element samlResponseElm) throws Exception {
		return SerializeSupport.prettyPrintXML(samlResponseElm);
	}

	public static String getSAMLAssertionInPrettyPrint(Element samlAssertionElm) throws Exception {
		return SerializeSupport.nodeToString(samlAssertionElm);
	}

	/**
	 * Fetch <saml2:Assertion> node from <saml2:Response> node.
	 * 
	 * @param samlResponse Stringified of <Saml2:Response> node
	 * @return
	 */
	public static String fetchSAMLAssertionFrom(String samlResponse) {
		String samlAssertionStr = null;
		try {
			samlAssertionStr = samlResponse.substring(samlResponse.indexOf("<saml2:Assertion"),

					samlResponse.indexOf("</saml2:Assertion>") + "</saml2:Assertion>".length());
		} catch (Exception ex) {
			System.err.println("Exception occurred while looking for <saml2:Assertion> in SAMLResponse " + ex);
			ex.printStackTrace();
		}
		return samlAssertionStr;
	}

	/**
	 * Build Issuer Object and with issuerId
	 * 
	 * @param issuerId
	 * @return
	 */
	private static Issuer buildIssuer(String issuerId) {
		IssuerBuilder issuerBuilder = new IssuerBuilder();
		Issuer issuer = issuerBuilder.buildObject();
		issuer.setValue(issuerId);
		return issuer;
	}

	/**
	 * Build org.opensaml.saml.saml2.core.Response object with provided input
	 * 
	 * @param jksFilePath            Path of .JKS file
	 * @param jksPassword            Password of .JKS file
	 * @param keyPassword            Key of a certificate
	 * @param certAlias              Alias of certificate in .JKS file
	 * @param issuerID               Issuer of Certificate
	 * @param entityID               NameID value in SAML Assertion to recognize the
	 *                               user
	 * @param audienceRestrictionURL The value of Audience in SAML Assertion where
	 *                               this will be validated at
	 * @param samlAuthnCtxClassRef
	 * @param assertionTimeoutInMin  Assertion Timeout in Minutes
	 * @return
	 * @throws Exception
	 */
	public static org.opensaml.saml.saml2.core.Response buildSAMLResponse(File jksFile, String jksPassword,
			String keyPassword, String certAlias, String issuerID, String entityID, String audienceRestrictionURL,
			String samlAuthnCtxClassRef, int assertionTimeoutInMin) throws Exception {
		org.opensaml.saml.saml2.core.Response samlResponse = null;

		XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();

		samlResponse = ((ResponseBuilder) builderFactory.getBuilder(Response.DEFAULT_ELEMENT_NAME)).buildObject();
		// Some SAML solutions do not accept the assertion(s) IDs (xs:ID) that start
		// with a coefficient or integer. This is a restriction that applies only to
		// first character of the string, specifically specifying the first character of
		// the string must be a letter or "_" only.
		samlResponse.setID("_" + UUID.randomUUID().toString());
		samlResponse.setIssueInstant(new DateTime());
		samlResponse.setVersion(SAMLVersion.VERSION_20);

		// build assertion
		Assertion assertion = buildSAMLAssertion(jksFile, jksPassword, keyPassword, certAlias, issuerID, entityID,
				audienceRestrictionURL, samlAuthnCtxClassRef, assertionTimeoutInMin);

		/* Add Assertion to Response */
		samlResponse.getAssertions().add(assertion);

		return samlResponse;
	}

	/**
	 * Build SAML Assertion object
	 * 
	 * @param jksFilePath
	 * @param jksPassword
	 * @param keyPassword
	 * @param certAlias
	 * @param issuerID
	 * @param entityID
	 * @param audienceRestrictionURL
	 * @param samlAuthnCtxClassRef
	 * @param assertionTimeoutInMin
	 * @return
	 * @throws Exception
	 */
	public static Assertion buildSAMLAssertion(File jksFile, String jksPassword, String keyPassword,
			String certAlias, String issuerID, String entityID, String audienceRestrictionURL,
			String samlAuthnCtxClassRef, int assertionTimeoutInMin) throws Exception {
		org.opensaml.saml.saml2.core.Assertion samlAssertion = null;

		XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();

		// initialize Assertion
		samlAssertion = initializeSAMLAssertion(builderFactory);

		// add Subject to Assertion
		samlAssertion.setSubject(buildSubject(builderFactory, entityID, assertionTimeoutInMin));

		// add Issuer to Assertion
		samlAssertion.setIssuer(buildIssuer(issuerID));

		// add Conditions to Assertion
		samlAssertion.setConditions(buildConditions(builderFactory, assertionTimeoutInMin, audienceRestrictionURL));

		// add AuthnticationStatement to Assertion
		samlAssertion.getAuthnStatements().add(buildAuthnStatement(builderFactory, samlAuthnCtxClassRef));

		// Build Credential with
		X509Credential credential = buildCredentialWith(jksFile, jksPassword, keyPassword, certAlias);

		// Add signature
		Signature signature = (Signature) builderFactory.getBuilder(Signature.DEFAULT_ELEMENT_NAME)
				.buildObject(Signature.DEFAULT_ELEMENT_NAME);

		KeyInfo keyInfo = (KeyInfo) builderFactory.getBuilder(KeyInfo.DEFAULT_ELEMENT_NAME)
				.buildObject(KeyInfo.DEFAULT_ELEMENT_NAME);
		X509Data data = (X509Data) builderFactory.getBuilder(X509Data.DEFAULT_ELEMENT_NAME)
				.buildObject(X509Data.DEFAULT_ELEMENT_NAME);
		org.opensaml.xmlsec.signature.X509Certificate cert = (org.opensaml.xmlsec.signature.X509Certificate) builderFactory
				.getBuilder(org.opensaml.xmlsec.signature.X509Certificate.DEFAULT_ELEMENT_NAME)
				.buildObject(org.opensaml.xmlsec.signature.X509Certificate.DEFAULT_ELEMENT_NAME);

		signature.setSigningCredential(credential);
		signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
		signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
		String encodedCertBytes = org.apache.xml.security.utils.Base64
				.encode(credential.getEntityCertificate().getEncoded());
		cert.setValue(encodedCertBytes);
		data.getX509Certificates().add(cert);
		keyInfo.getX509Datas().add(data);
		signature.setKeyInfo(keyInfo);

		// signature.setSigningCredential(credential);
		// signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
		// signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

		samlAssertion.setSignature(signature);

		((SAMLObjectContentReference) signature.getContentReferences().get(0))
				.setDigestAlgorithm(EncryptionConstants.ALGO_ID_DIGEST_SHA256);

		// sign the assertion
		XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(samlAssertion).marshall(samlAssertion);
		Signer.signObject(signature);

		return samlAssertion;
	}

	/**
	 * Initialize the SAML Assertion with the default attrributes such as ID and
	 * IssueInstant
	 * 
	 * @param builderFactory
	 * @return
	 */
	private static Assertion initializeSAMLAssertion(XMLObjectBuilderFactory builderFactory) {
		// Initialize Assertion
		Assertion assertion = ((AssertionBuilder) builderFactory.getBuilder(Assertion.DEFAULT_ELEMENT_NAME))
				.buildObject();
		/*
		 * Some SAML solutions do not accept the assertion(s) IDs (xs:ID) that start
		 * with a coefficient or integer. This is a restriction that applies only to
		 * first character of the string, specifically specifying the first character of
		 * the string must be a letter or "_" only.
		 */
		String uid = UUID.randomUUID().toString();
		assertion.setID("_" + uid);
		assertion.setIssueInstant(new DateTime());
		return assertion;
	}

	/**
	 * Build SAML Subject and SubjectConfirmation with entityID
	 * 
	 * @param builderFactory
	 * @param entityID
	 * @param timeoutMin
	 * @return
	 */
	private static Subject buildSubject(XMLObjectBuilderFactory builderFactory, String entityID, int timeoutMin) {
		// Initialize Subject
		Subject subject = ((SubjectBuilder) builderFactory.getBuilder(Subject.DEFAULT_ELEMENT_NAME)).buildObject();

		// Initialize NameID
		NameID nameID = ((NameIDBuilder) builderFactory.getBuilder(NameID.DEFAULT_ELEMENT_NAME)).buildObject();
		nameID.setValue(entityID);

		// Use the 'default' format to allow any type of data (e.g. emailaddress,
		// anytext)
		nameID.setFormat(NameIDType.UNSPECIFIED);

		// add NameID to subject
		subject.setNameID(nameID);

		// Initialize SubjectConfirmationData
		SubjectConfirmation subjConfirm = ((SubjectConfirmationBuilder) builderFactory
				.getBuilder(SubjectConfirmation.DEFAULT_ELEMENT_NAME)).buildObject();
		subjConfirm.setMethod(SAML_METHOD);

		// Initialize SubjectConfirmationData
		SubjectConfirmationData subjConfirmData = ((SubjectConfirmationDataBuilder) builderFactory
				.getBuilder(SubjectConfirmationData.DEFAULT_ELEMENT_NAME)).buildObject();
		DateTime dateTime = new DateTime();
		DateTime afterTime = dateTime.plusMinutes(timeoutMin);
		subjConfirmData.setNotBefore(dateTime);
		subjConfirmData.setNotOnOrAfter(afterTime);
		subjConfirm.setSubjectConfirmationData(subjConfirmData);

		// add subjConfirm to subject
		subject.getSubjectConfirmations().add(subjConfirm);
		return subject;
	}

	/**
	 * Build SAML Conditions for Assertion
	 * 
	 * @param builderFactory
	 * @param timeoutMin
	 * @param audienceRestrictionURL
	 * @return
	 */
	private static Conditions buildConditions(XMLObjectBuilderFactory builderFactory, int timeoutMin,
			String audienceRestrictionURL) {
		// Initialize Conditions
		Conditions conditions = ((ConditionsBuilder) builderFactory.getBuilder(Conditions.DEFAULT_ELEMENT_NAME))
				.buildObject();
		DateTime dateTime = new DateTime();
		DateTime afterTime = dateTime.plusMinutes(timeoutMin);
		conditions.setNotBefore(dateTime);
		conditions.setNotOnOrAfter(afterTime);

		// Initialize AudienceRestriction
		AudienceRestriction audienceRestriction = ((AudienceRestrictionBuilder) builderFactory
				.getBuilder(AudienceRestriction.DEFAULT_ELEMENT_NAME)).buildObject();

		Audience audience = ((AudienceBuilder) builderFactory.getBuilder(Audience.DEFAULT_ELEMENT_NAME)).buildObject();
		audience.setAudienceURI(audienceRestrictionURL);
		audienceRestriction.getAudiences().add(audience);

		conditions.getAudienceRestrictions().add(audienceRestriction);
		// OneTimeUse oneTimeUse = ((OneTimeUseBuilder)
		// builderFactory.getBuilder(OneTimeUse.DEFAULT_ELEMENT_NAME)).buildObject();
		// TODO Add OneTimeUse to Conditions

		return conditions;
	}

	/**
	 * Build AuthnStatement for Assertion
	 * 
	 * @param builderFactory
	 * @param samlAuthnCtxClassRef
	 * @return
	 */
	private static AuthnStatement buildAuthnStatement(XMLObjectBuilderFactory builderFactory,
			String samlAuthnCtxClassRef) {
		// Initialize AuthnStatement
		AuthnStatement authnStmt = ((AuthnStatementBuilder) builderFactory
				.getBuilder(AuthnStatement.DEFAULT_ELEMENT_NAME)).buildObject();
		authnStmt.setAuthnInstant(new DateTime());

		// Initialize AuthnContext
		AuthnContext authnContext = ((AuthnContextBuilder) builderFactory.getBuilder(AuthnContext.DEFAULT_ELEMENT_NAME))
				.buildObject();

		AuthnContextClassRef authnContextClassRef = ((AuthnContextClassRefBuilder) builderFactory
				.getBuilder(AuthnContextClassRef.DEFAULT_ELEMENT_NAME)).buildObject();
		// add Auth Method
		authnContextClassRef.setAuthnContextClassRef(samlAuthnCtxClassRef);
		authnContext.setAuthnContextClassRef(authnContextClassRef);

		authnStmt.setAuthnContext(authnContext);

		return authnStmt;
	}

	private static X509Credential buildCredentialWith(File jksFile, String keystorePwd, String keyPwd,
			String certAlias) throws Exception {
		X509Credential x509Credential = null;
		KeyPair keyPair = PublicKeyUtil.getKeyPairFromKeyStore(jksFile, keystorePwd, keyPwd, certAlias);

		PrivateKey privateKey = keyPair.getPrivate();

		KeyStore keystore = PublicKeyUtil.getKeyStore(jksFile, keystorePwd);

		X509Certificate certificate = PublicKeyUtil.getX509Certificate(keystore, certAlias, keyPwd);

		x509Credential = new BasicX509Credential(certificate, privateKey);
		return x509Credential;
	}
}