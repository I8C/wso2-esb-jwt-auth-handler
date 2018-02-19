package be.i8c.wso2.esb;
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
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Iterator;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMNode;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.synapse.SynapseException;

/*
 * Checks a JWT coming from the WSO2 API Manager.
 * Validates that JWT was signed by the WSO2 API Manager and the issuer claim matches with
 * what was configured in the API Manager.
 * 
 */
public class JwtValidator {

  private Log log = LogFactory.getLog(getClass());

  private static final SimpleDateFormat belgianDateFormatter = new SimpleDateFormat(
      "HH:mm:ss dd-MMM-yyyy z");

  public static final String jwtValidatorRootConfigKey = "JwtAuthHandlerConfig";

  // aliases of one or more WSO2 AM public key certificates in keystore
  // separated by ,
  private String aliases;
  public static final String aliasesKey = "Aliases";

  // value of the issuer in the JWT to check
  private String jwtIssuer;
  public static final String jwtIssuerKey = "JwtIssuer";

  // name of the HTTP header containing the JWT token
  private String jwtHttpHeader;
  public static final String jwtHttpHeaderKey = "JwtHttpHeader";

  // filename and location of the keystore containing the public key to validate the JWT signature
  private String keystoreFilename;
  public static final String keystoreFilenameKey = "KeystoreFilename";

  // password of the keystore
  private String keystorePassword;
  public static final String keystorePasswordKey = "KeystorePassword";

  // actual KeyStore object parsed from keystoreFilename
  private KeyStore keystore;

  /**
   * Constructor that allows to configure the object based on an XML config file obtained from the
   * WSO2 ESB Registry.
   * 
   * @param rootConfigNode
   *          OMNode containing an XML document that matches the following format:
   *          <JwtAuthHandlerConfig>
   *            <Aliases>wso2carbonQA,wso2carbonPROD</Aliases>
   *            <JwtHttpHeader>X-JWT-Assertion</JwtHttpHeader>
   *            <JwtIssuer>wso2.org/products/am</JwtIssuer>
   *            <KeystoreFilename>/opt/wso2/wso2am-2.1.0-update8/repository/resources/security/wso2carbon.jks</KeystoreFilename>
   *            <KeystorePassword>wso2carbon</KeystorePassword>
   *          </JwtAuthHandlerConfig>
   */
  public JwtValidator(OMNode rootConfigNode) {
    if (rootConfigNode == null) {
      throw new SynapseException("Initialization XML should not be null!");
    } else {
      if (rootConfigNode.getType() == OMNode.ELEMENT_NODE) {
        OMElement rootConfigElement = (OMElement) rootConfigNode;
        if (rootConfigElement.getLocalName() == jwtValidatorRootConfigKey) {
          Iterator<OMElement> i = rootConfigElement.getChildElements();
          while (i.hasNext()) {
            OMElement rootChild = i.next();
            switch (rootChild.getLocalName()) {
              case aliasesKey:
                setAliases(rootChild.getText());
                break;
              case jwtIssuerKey:
                setJwtIssuer(rootChild.getText());
                break;
              case jwtHttpHeaderKey:
                setJwtHttpHeader(rootChild.getText());
                break;
              case keystoreFilenameKey:
                setKeystoreFilename(rootChild.getText());
                break;
              case keystorePasswordKey:
                setKeystorePassword(rootChild.getText());
                break;
              default:
                log.warn("Unexpected child element " + rootChild.getLocalName() + "!");
            }
          }
          initialize();
        } else {
          throw new SynapseException(
              "Initialization XML root element " + rootConfigElement.getLocalName()
              + " doesn't match expected value " + jwtValidatorRootConfigKey + "!");
        }
      } else {
        throw new SynapseException("Initialization XML doesn't seem to contain a root element!");
      }

    }
  }

  private void initialize() {
    if (getKeystoreFilename() == null || getKeystoreFilename().equals("")) {
      throw new SynapseException(
          keystoreFilenameKey + " should contain the path to a valid .jks file!");
    }
    if (getKeystorePassword() == null || getKeystorePassword().equals("")) {
      throw new SynapseException(keystorePasswordKey + " should contain the password of the file "
          + getKeystoreFilename());
    }
    if (getJwtIssuer() == null || getJwtIssuer().equals("")) {
      throw new SynapseException(jwtIssuerKey
          + " should contain the value of the issuer claim configured by the WSO2 API Manager!");
    }
    if (getJwtHttpHeader() == null || getJwtHttpHeader().equals("")) {
      throw new SynapseException(jwtHttpHeaderKey
          + " should contain the name of the HTTP that contains the JWT sent by the WSO2 API"
          + " Manager! Typically this defaults to X-JWT-Assertion.");
    }
    if (getAliases() == null || getAliases().equals("")) {
      throw new SynapseException(
          aliasesKey + " should contain a comma separated list of certificate aliases available in "
              + getKeystoreFilename() + " against which the JWT in " + getJwtHttpHeader()
              + " is validated!");
    }

    InputStream file = null;
    try {
      log.debug("Loading keystore from file " + getKeystoreFilename());
      file = new FileInputStream(getKeystoreFilename());
      keystore = KeyStore.getInstance(KeyStore.getDefaultType());
      keystore.load(file, getKeystorePassword().toCharArray());
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

  /**
   * Verifies the signature on the JWT token.
   * 
   * @param signedJwtAsString
   *          A JWT as String
   * @return true of JWT token valid, false otherwise
   * @throws KeyStoreException
   */
  public boolean isValidJwt(String signedJwtAsString) throws KeyStoreException {

    if (log.isDebugEnabled()) {
      log.debug("Validating JWT = " + signedJwtAsString
          + " against public key in certificate(s) with alias(es) = " + getAliases()
          + " in keystore " + getKeystoreFilename());
    }
    
    if (getAliases() == null || keystore == null) {
      log.error("JwtValidator object not properly initialized!");
      return false;
    } 

    try {
      SignedJWT signedJwt = SignedJWT.parse(signedJwtAsString);
      for (String alias : getAliases().split(",")) {
        // Get certificate of public key
        Certificate cert = keystore.getCertificate(alias);
        if (cert == null) {
          log.error("Certificate " + alias + " could not be found in keystore "
              + getKeystoreFilename() + "!");
          return false;
        }

        // Get public key
        RSAPublicKey publicKey = (RSAPublicKey) cert.getPublicKey();
        JWSVerifier verifier = new RSASSAVerifier(publicKey);

        // If signature verification fails, try next alias
        if (signedJwt.verify(verifier)) {
          JWTClaimsSet jwtClaimsSet = signedJwt.getJWTClaimsSet();

          // JWT exp claim always seems to be older than sysdate, so don't add a check for it.
          if (log.isTraceEnabled()) {
            log.trace("JWT exp = " + belgianDateFormatter.format(jwtClaimsSet.getExpirationTime())
                + ", sysdate = " + belgianDateFormatter.format(new Date()));
          }

          // Check if issuer in claim corresponds to configured expected value.
          if (!jwtClaimsSet.getIssuer().equals(jwtIssuer)) {
            log.info("Issuer in JWT  = " + jwtClaimsSet.getIssuer()
                + " doesn't match expected value = " + jwtIssuer);
            return false;
          } else {
            return true;
          }
        }
      }    
    } catch (ParseException e) {
      if (log.isDebugEnabled()) {
        log.debug("Exception while parsing JWT: " + e.getMessage());
      }
      // Jwt provided by consumer doesn't seem to have correct format
      return false;
    } catch (JOSEException e) {
      if (log.isDebugEnabled()) {
        log.debug("Exception while checking JWT signature: " + e.getMessage());
      }
      // Jwt provided by consumer doesn't seem to have correct signature
      return false;
    }

    log.info("All signature verifications failed: access denied");
    return false;
  }

  // Below only getters and setters

  public String getAliases() {
    return aliases;
  }

  public void setAliases(String aliases) {
    this.aliases = aliases;
  }

  public String getJwtHttpHeader() {
    return jwtHttpHeader;
  }

  public void setJwtHttpHeader(String jwtHttpHeader) {
    this.jwtHttpHeader = jwtHttpHeader;
  }

  public String getJwtIssuer() {
    return jwtIssuer;
  }

  public void setJwtIssuer(String jwtIssuer) {
    this.jwtIssuer = jwtIssuer;
  }

  public String getKeystoreFilename() {
    return keystoreFilename;
  }

  public void setKeystoreFilename(String keystoreFilename) {
    this.keystoreFilename = keystoreFilename;
  }

  public String getKeystorePassword() {
    return keystorePassword;
  }

  public void setKeystorePassword(String keystorePassword) {
    this.keystorePassword = keystorePassword;
  }

}
