package com.roblox.rcs;
/*  
 * Copyright 2018 i8c N.V. (www.i8c.be)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;

import java.security.KeyStoreException;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Iterator;

import org.apache.axiom.om.OMElement;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.roblox.rcs.Utils;

/*
 * Checks a JWT coming from the WSO2 API Manager.
 * Validates that JWT was signed by the WSO2 API Manager and the issuer claim matches with
 * what was configured in the API Manager.
 * 
 */
public class JwtValidator {

  private Log log = LogFactory.getLog(getClass());

  private ArrayList<Keystore> keystores;
  
  private boolean enforceExpiration;

  public JwtValidator(OMElement config) {
	  
	  enforceExpiration = Boolean.parseBoolean(Utils.GetAttributeValue("EnforceJwtExpiration", config));
	  
      Iterator<OMElement> i = Utils.GetElement("Keystores", config).getChildElements();
      
      keystores = new ArrayList<Keystore>();
      
      while (i.hasNext()) {
        OMElement keystoreElement = i.next();
        String location = Utils.GetElement("Location", keystoreElement).getText();
        String password = Utils.GetVaultValue(Utils.GetAttributeValue("KeystoreVaultKey", keystoreElement));
        log.debug("Adding aliases");
        ArrayList<String> aliases = Utils.GetChildElementValues(
				Utils.GetElement("Aliases", keystoreElement)
				);
        aliases.trimToSize();
        log.debug("Aliases to add count: " + aliases.size());
        keystores.add( new Keystore(location, password, null, aliases));
      }
  }

  /**
   * Verifies the signature on the JWT token.
   * 
   * @param signedJwtAsString
   *          A JWT as String
   * @return true of JWT token valid, false otherwise
   * @throws KeyStoreException
   */
  public boolean isValidJwt(SignedJWT jwt)  {

    if (keystores == null || keystores.isEmpty()) {
      log.error("JwtValidator object not properly initialized!");
      return false;
    } 

	boolean isValid = false;
	for (Keystore keystore : keystores) {
		for (String alias : keystore.getValidAlaises()) {
			try {
				log.debug("Testing for public key " + alias);
			RSAPublicKey publicKey = (RSAPublicKey) keystore.GetPublicKey(alias);
			if (publicKey == null) { log.debug("Public key is null"); }
	        JWSVerifier verifier = new RSASSAVerifier(publicKey);
	        isValid = jwt.verify(verifier);
	        
	        if (isValid) {
	        	log.debug("JWT signature is valid");
	        	break;
	        }
		    } catch (JOSEException e) {
		        log.warn(e);
		      } catch (KeyStoreException e) {
		  		log.warn(e);
		  	}
		}
	    if (isValid) {
	    	break;
	    }
	}
	
	// TODO Need to re-add expiration validation
	log.debug("Reached end of JwtValidator");
	return isValid;
  }

}
