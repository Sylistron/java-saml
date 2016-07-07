package com.onelogin;

import java.io.ByteArrayInputStream;
import java.io.UnsupportedEncodingException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import org.apache.commons.codec.binary.Base64;

public class AccountSettings {
	private String certificate;
	private String spPrivateKey;
	private Certificate idp_cert;
	private RSAPrivateKey sp_private_key;
	private String idp_sso_target_url;
	private String idp_signing_algo;
	
	public String getCertificate() {
		return certificate;
	}
	public void setCertificate(String certificate) {
		this.certificate = certificate;
	}
	public String getSpPrivateKey() {
		return spPrivateKey;
	}
	public void setSpCertificate(String privateKey) {
		this.spPrivateKey = privateKey;
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
	 * Loads private key from a base64 encoded string
	 * @param private key an base64 encoded string.
 	 * @throws NoSuchAlgorithmException 
 	 * @throws UnsupportedEncodingException 
 	 * @throws InvalidKeySpecException 
	 */
 	public void loadSpPrivateKey(String privateKey) throws InvalidKeySpecException, UnsupportedEncodingException, NoSuchAlgorithmException {
		loadSpPrivateKey(privateKey, true);
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
	
	public void loadSpPrivateKey(String privateKey, boolean isBase64) throws InvalidKeySpecException, UnsupportedEncodingException, NoSuchAlgorithmException {
		byte[] privateKeyBytes;
		if (isBase64) {
			privateKeyBytes = Base64.decodeBase64(privateKey);
        } else {
        	privateKeyBytes = privateKey.getBytes("UTF-8");        			
        }
		
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        
        this.sp_private_key = (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
    }
    
	public Certificate getIdpCert() throws CertificateException {
		if(this.idp_cert == null){
			loadCertificate(this.certificate);
		}
		return this.idp_cert;
	}
	
	public RSAPrivateKey getSpPK() throws InvalidKeySpecException, UnsupportedEncodingException, NoSuchAlgorithmException {
		if(this.sp_private_key == null){
			loadSpPrivateKey(this.spPrivateKey);
		}
		return this.sp_private_key;
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
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeySpecException 
	 */
	public RSAPrivateKey getSpPrivateKey(byte[] privateKey) throws CertificateException, NoSuchAlgorithmException, InvalidKeySpecException {
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKey);
        
        this.sp_private_key = (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
        return sp_private_key; 
	}
}