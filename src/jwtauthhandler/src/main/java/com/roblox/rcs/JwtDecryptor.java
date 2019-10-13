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

import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jose.JWEObject.State;

import java.security.KeyStoreException;
import java.util.Iterator;
import java.util.ArrayList;

import org.apache.axiom.om.OMElement;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;


import com.roblox.rcs.Keystore;

/*
 * Checks a JWT coming from the WSO2 API Manager.
 * Validates that JWT was signed by the WSO2 API Manager and the issuer claim matches with
 * what was configured in the API Manager.
 * 
 */
public class JwtDecryptor {

  private Log log = LogFactory.getLog(getClass());
  
  private ArrayList<Keystore> keystores;
  
  public JwtDecryptor(OMElement rootConfigElement) {
          Iterator<OMElement> i = Utils.GetElement("Keystores", rootConfigElement).getChildElements();
          
          keystores = new ArrayList<Keystore>();
          
          while (i.hasNext()) {
            OMElement keystoreElement = i.next();
            String location = Utils.GetElement("Location", keystoreElement).getText();
            String password = Utils.GetVaultValue(Utils.GetAttributeValue("KeystoreVaultKey", keystoreElement));
            String certPassword = Utils.GetVaultValue(Utils.GetAttributeValue("PrivateKeyVaultKey", keystoreElement));
            
            keystores.add(
            		new Keystore(location, password, certPassword, Utils.GetChildElementValues(
            				Utils.GetElement("Aliases", keystoreElement)
            				)
        				)
            		);
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
  public boolean Decrypt(EncryptedJWT jwt)  {

	  for (Keystore keystore : keystores) {
		  try {
			  RSADecrypter dec = new RSADecrypter(keystore.GetPrivateKey());
			  jwt.decrypt(dec);
			  if (jwt.getState() == State.DECRYPTED) {
				  return true;
			  }
		  }
		  catch (Exception e) {
			  log.error(e);
		  }
	  }
      return false;

  }



}
