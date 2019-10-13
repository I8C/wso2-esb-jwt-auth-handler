package com.roblox.rcs;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.ArrayList;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.synapse.SynapseException;

public class Keystore {
	
	private Log log = LogFactory.getLog(getClass());
	  
	private KeyStore keystore;
	
	private String certKeyAlias;
	
	private String certKeyPass;
	
	private ArrayList<String> aliases;
	
	public Keystore(String keystorePath, String keystorePassword, String privateKeyPassword, ArrayList<String> allowedAliases) throws SynapseException {
		FileInputStream file = null;
	    try {
	        log.debug("Loading keystore from file " + keystorePath);
	        file = new FileInputStream(keystorePath);
        	keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        	log.debug("Keystore created of type " + keystore.getDefaultType() + "; Loading...");
        	log.debug("using password : " + keystorePassword);
	        keystore.load(file, keystorePassword.toCharArray());
	        log.debug("Keystore loaded");
	        
	        aliases = new ArrayList<String>();
	        Iterator<String> i = allowedAliases.iterator();
	        while (i.hasNext())
	        {
	        	String a = i.next();
	        	if (keystore.containsAlias(a)) {
	        		aliases.add(a);
	        	}
	        }
	        
	        Enumeration<String> e = keystore.aliases();
	        while (e.hasMoreElements()) {
	        	String a = e.nextElement();
	        	if (keystore.isKeyEntry(a)) {
	        		certKeyAlias = a;
	        		break;
	        	}
	        }
	        
	        certKeyPass = privateKeyPassword;
	      } catch (NoSuchAlgorithmException | CertificateException | IOException | KeyStoreException e) {
	        log.error("Initialization error: " + e.getMessage());
	        throw new SynapseException(e);
	      } finally {
	        try {
	          if (file != null) {
	            file.close();
	          }
	        } catch (IOException e) {
	          // ignore error
	        }
	      }
	}
	
	public RSAPublicKey GetPublicKey(String certAlias) throws KeyStoreException {
        Certificate cert = keystore.getCertificate(certAlias);
        
        if (cert == null) {
          log.error("Certificate " + certAlias + " could not be found in keystore");
          return null;
        }

        // Get public key
        RSAPublicKey publicKey = (RSAPublicKey) cert.getPublicKey();
        
        return publicKey;
	}
	
	public RSAPrivateKey GetPrivateKey() {
		
		if (certKeyAlias == null || certKeyPass == null) {
			log.error("Keystore is not configured for decryption");
		}
		
        Key key = null;
		try {
			key = keystore.getKey(certKeyAlias, certKeyPass.toCharArray());
		} catch (Exception e) {
			log.error(e);
		}
        
        if (key == null) {
          log.error("Private key " + certKeyAlias + " could not be retrieved from the keystore");
          return null;
        } else if (!(key instanceof PrivateKey)) {
            log.error("Private key " + certKeyAlias + " does not contain a private key");
            return null;
        }

        return (RSAPrivateKey) key;
	}
	
	public ArrayList<String> getValidAlaises() {
		return aliases;
	}
	

}
