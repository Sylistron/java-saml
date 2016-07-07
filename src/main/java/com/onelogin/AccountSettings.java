package com.onelogin;

import java.io.ByteArrayInputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

import org.apache.commons.codec.binary.Base64;


public class AccountSettings {
	private String certificate;
	private String spCertificate;
	private Certificate idp_cert;
	private Certificate sp_cert;
	private String idp_sso_target_url;
	private String idp_signing_algo;
	
	public String getCertificate() {
		return certificate;
	}
	public void setCertificate(String certificate) {
		this.certificate = certificate;
	}
	public String getSpCertificate() {
		return spCertificate;
	}
	public void setSpCertificate(String certificate) {
		this.spCertificate = certificate;
	}
	public String getIdp_sso_target_url() {
		return idp_sso_target_url;
	}
	public void setIdpSsoTargetUrl(String idp_sso_target_url) {
		this.idp_sso_target_url = idp_sso_target_url;
	}
	
	
	public String getIdp_signing_algo() {
		return idp_signing_algo;
	}
	public void setIdp_signing_algo(String idp_signing_algo) {
		this.idp_signing_algo = idp_signing_algo;
	}
	/**
	 * Loads certificate from a base64 encoded string
	 * @param certificate an base64 encoded string.
	 */
 	public void loadCertificate(String certificate) throws CertificateException {
		loadCertificate(certificate, true);
	}
	
 	/**
	 * Loads certificate from a base64 encoded string
	 * @param certificate an base64 encoded string.
	 */
 	public void loadSpCertificate(String certificate) throws CertificateException {
		loadSpCertificate(certificate, true);
	}
 	
	public void loadCertificate(String certificate, boolean isBase64) throws CertificateException {
        CertificateFactory fty = CertificateFactory.getInstance("X.509");
        byte[] cert = certificate.getBytes();
        if (isBase64) {
            cert = Base64.decodeBase64(cert);
        }
        ByteArrayInputStream bais = new ByteArrayInputStream(cert);
        this.idp_cert = fty.generateCertificate(bais);
    }
	
	public void loadSpCertificate(String certificate, boolean isBase64) throws CertificateException {
        CertificateFactory fty = CertificateFactory.getInstance("X.509");
        byte[] cert = certificate.getBytes();
        if (isBase64) {
            cert = Base64.decodeBase64(cert);
        }
        ByteArrayInputStream bais = new ByteArrayInputStream(cert);
        this.sp_cert = fty.generateCertificate(bais);
    }
    
	public Certificate getIdpCert() throws CertificateException {
		if(this.idp_cert == null){
			loadCertificate(this.certificate);
		}
		return this.idp_cert;
	}
	
	public Certificate getSpCert() throws CertificateException {
		if(this.sp_cert == null){
			loadSpCertificate(this.spCertificate);
		}
		return this.sp_cert;
	}
	
	/**
	 * load and get a certificate from a encoded base64 byte array.
	 * @param certificate an encoded base64 byte array.
	 * @throws CertificateException In case it can't load the certificate.
	 */
	public Certificate getCert(byte[] certificate) throws CertificateException {
		CertificateFactory fty = CertificateFactory.getInstance("X.509");
		ByteArrayInputStream bais = new ByteArrayInputStream(Base64.decodeBase64(certificate));
		idp_cert = fty.generateCertificate(bais);
		return idp_cert;
	}
	
	/**
	 * load and get a certificate from a encoded base64 byte array.
	 * @param certificate an encoded base64 byte array.
	 * @throws CertificateException In case it can't load the certificate.
	 */
	public Certificate getSpCert(byte[] certificate) throws CertificateException {
		CertificateFactory fty = CertificateFactory.getInstance("X.509");
		ByteArrayInputStream bais = new ByteArrayInputStream(Base64.decodeBase64(certificate));
		sp_cert = fty.generateCertificate(bais);
		return sp_cert;
	}
}
