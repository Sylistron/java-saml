package com.onelogin.saml;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Random;
import java.util.TimeZone;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;

import org.apache.commons.codec.binary.Base64;

import com.onelogin.AccountSettings;
import com.onelogin.AppSettings;

public class AuthRequest {

	protected final String id;
	protected final String issueInstant;
	protected final AppSettings appSettings;
	protected AccountSettings accountSettings;
	protected static final int base64 = 1;
	protected Deflater deflater;

	public AuthRequest(AppSettings appSettings, AccountSettings accSettings){
		this.appSettings = appSettings;
		this.accountSettings = accSettings;
		//id="_"+UUID.randomUUID().toString();
		
		Random r = new Random();
        id = 'a' + Long.toString(Math.abs(r.nextLong()), 20) + Long.toString(Math.abs(r.nextLong()), 19);
		
		SimpleDateFormat simpleDf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
		simpleDf.setTimeZone(TimeZone.getTimeZone("UTC"));
		issueInstant = simpleDf.format(new Date());
	}

	public byte[] getRequest(int format) throws XMLStreamException, IOException {
		byte[] result = null;

		ByteArrayOutputStream baos = new ByteArrayOutputStream();

		XMLOutputFactory factory = XMLOutputFactory.newInstance();
		XMLStreamWriter writer = factory.createXMLStreamWriter(baos);
		writer.writeStartDocument();
		writer.writeStartElement("saml2p", "AuthnRequest", "urn:oasis:names:tc:SAML:2.0:protocol");
		writer.writeNamespace("saml2p","urn:oasis:names:tc:SAML:2.0:protocol");

		writer.writeAttribute("ID", id);
		writer.writeAttribute("Version", "2.0");
		writer.writeAttribute("IssueInstant", this.issueInstant);
		writer.writeAttribute("ProtocolBinding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
		writer.writeAttribute("AssertionConsumerServiceURL", this.appSettings.getAssertionConsumerServiceUrl());
		
		// ADFS attributes		
		if (accountSettings.isAdfs()) {
			writer.writeAttribute("Destination", this.accountSettings.getIdp_sso_target_url()); 
			writer.writeAttribute("ForceAuthn", "false"); 
			writer.writeAttribute("IsPassive", "false");
		}		
		// /ADFS attributes

		writer.writeStartElement("saml2","Issuer","urn:oasis:names:tc:SAML:2.0:assertion");
		writer.writeNamespace("saml2","urn:oasis:names:tc:SAML:2.0:assertion");
		writer.writeCharacters(this.appSettings.getIssuer());
		writer.writeEndElement();

		// NON-ADFS stuff
		if (!accountSettings.isAdfs()) {
			writer.writeStartElement("samlp", "NameIDPolicy", "urn:oasis:names:tc:SAML:2.0:protocol");

			writer.writeAttribute("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");
			writer.writeAttribute("AllowCreate", "true");
			writer.writeEndElement();
			
			writer.writeStartElement("samlp","RequestedAuthnContext","urn:oasis:names:tc:SAML:2.0:protocol");

			writer.writeAttribute("Comparison", "exact");

			writer.writeStartElement("saml","AuthnContextClassRef","urn:oasis:names:tc:SAML:2.0:assertion");
			writer.writeNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");
			writer.writeCharacters("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");
			writer.writeEndElement();

			writer.writeEndElement();
		}
		// /NON-ADFS stuff
		
		writer.writeEndElement();
		writer.flush();
                
		result = baos.toByteArray();
		return result;
	}

	protected String encodeSAMLRequest(byte[] pSAMLRequest) throws RuntimeException {

		Base64 base64Encoder = new Base64();

		try {
			ByteArrayOutputStream byteArray = new ByteArrayOutputStream();
			Deflater deflater = new Deflater(Deflater.DEFAULT_COMPRESSION, true);

			DeflaterOutputStream def = new DeflaterOutputStream(byteArray, deflater);
			def.write(pSAMLRequest);
			def.close();
			byteArray.close();

			String stream = new String(base64Encoder.encode(byteArray.toByteArray()));

			return stream.trim();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}	
	
	public String getSSOurl(String relayState) throws UnsupportedEncodingException, XMLStreamException, IOException {
		
		byte[] samlRequestBytes = getRequest(base64);
		
		String encodedSamlRequest = encodeSAMLRequest(samlRequestBytes);
		
		String urlEncodedSamlRequest = URLEncoder.encode(encodedSamlRequest,"UTF-8").trim();
		
		String finalSignatureValue = "";
		
		// sign if necessary
		if (accountSettings.getSpPrivateKey() != null) {
			try {
				// determin our SigAlg
				String urlEncodedSigAlg = URLEncoder.encode(Utils.getAlgoNS(accountSettings.getIdp_signing_algo()) + accountSettings.getIdp_signing_algo(),"UTF-8");
				
				// let's build the query string for signing
				String strSignature = "SAMLRequest=" + urlEncodedSamlRequest;
				
				if (relayState != null && !relayState.isEmpty()) {
					strSignature += "&RelayState=" + relayState;
				}
				
				// append our SigAlg
				strSignature += "&SigAlg=" + urlEncodedSigAlg;
				
				// sign the query string
				byte[] signedSamlRequestBytes = Utils.sign(accountSettings.getIdp_signing_algo(), accountSettings.getSpPK(), strSignature);
				
				Base64 base64Encoder = new Base64();
				String encodedSignedSamlRequest = new String(base64Encoder.encode(signedSamlRequestBytes));
				
				String urlEncodedSignedSamlRequest = URLEncoder.encode(encodedSignedSamlRequest,"UTF-8");
				
				finalSignatureValue = "&SigAlg=" + urlEncodedSigAlg + "&Signature=" + urlEncodedSignedSamlRequest;
				
			} catch (Exception e) {
				//TODO refactor exception handling?
				e.printStackTrace();
				throw new UnsupportedEncodingException(e.getMessage());
			}
		}
		
		String ssourl = accountSettings.getIdp_sso_target_url()+"?SAMLRequest=" + urlEncodedSamlRequest + finalSignatureValue;
		
		if(relayState != null && !relayState.isEmpty()) {
			ssourl = ssourl + "&RelayState=" + relayState;
		}
		
		return ssourl;
	}
	
	public String getSSOurl() throws UnsupportedEncodingException, XMLStreamException, IOException{		
		return getSSOurl(null);
	}
	
}
