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

import java.util.Map;
import java.text.ParseException;


import org.apache.axiom.om.OMElement;
import org.apache.commons.httpclient.util.HttpURLConnection;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.synapse.ManagedLifecycle;
import org.apache.synapse.MessageContext;
import org.apache.synapse.SynapseException;
import org.apache.synapse.core.SynapseEnvironment;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.core.axis2.Axis2Sender;
import org.apache.synapse.registry.Registry;
import org.apache.synapse.rest.AbstractHandler;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.EncryptedJWT;

import be.i8c.wso2.esb.JwtDecryptor;
import be.i8c.wso2.esb.JwtClaimsMap;

import be.i8c.wso2.esb.Utils;

/*
 * Implements a WSO2 ESB security handler as described in 
 * https://docs.wso2.com/display/ESB490/Securing+APIs.
 * See also:
 *  - https://docs.wso2.com/display/AM200/Writing+Custom+Handlers
 *  - https://github.com/wso2/carbon-appmgt/blob/master/components/org.wso2.carbon.appmgt.gateway/src/main/java/org/wso2/carbon/appmgt/gateway/handlers/throttling/APIThrottleHandler.java
 *  
 * Expects a JWT from the WSO2 API Manager as input with each request
 * (see also: https://docs.wso2.com/display/AM210/Passing+Enduser+Attributes+to+the+Backend+Using+JWT).
 * 
 * Usage:
 * Add the following section at the bottom of your <api></api> config:
 * <handlers>
 *    <handler class="be.i8c.wso2.esb.JwtAuthHandler">
 *       <property name="configKey" 
 *       value="conf:/repository/components/be.i8c.wso2.esb/JwtAuthHandlerConfig.xml"/> 
 *    </handler>
 * </handlers>
 * 
 * The config file to which the configKey property points in the registry of the ESB,
 * should contain the following XML structure. Note the "..VaultKey" attributes which
 * are NOT direct values but aliases to encrypted entries in the ESB Secure Vault.
 * (The following is not * prefixed to facilitate a copy/paste deployment)
 <JwtAuthHandlerConfig JwtType="encrypted">
  <Keystores>
    <!-- for JwtType="encrypted" the private key is required -->
    <Keystore KeystoreVaultKey="wso2carbon" PrivateKeyVaultKey="wso2carbon">
      C:\Program Files\WSO2\wso2ei-6.4.0\repository\resources\security\wso2carbon.jks
    </Keystore>
    <!-- For JwtType="signed" where only the public key is required 
    <Keystore KeystoreVaultKey="wso2carbon" CertificateAlias="wso2carbon">
      C:\Program Files\WSO2\wso2ei-6.4.0\repository\resources\security\wso2carbon.jks
    </Keystore>
    -->
  </Keystores>
  <JwtHttpHeader>X-JWT-Assertion</JwtHttpHeader>
  <JwtIssuer>wso2.org/products/am</JwtIssuer>
  <JwtClaimsMap>
    <Map>
      <JwtClaim>http://wso2.org/claims/subscriber</JwtClaim>
      <ContextProperty>username</ContextProperty>
      <Required>true</Required>
    </Map>
      <Map>
      <JwtClaim>http://wso2.org/claims/role</JwtClaim>
      <ContextProperty>roles</ContextProperty>
      <Required>true</Required>
    </Map>
  </JwtClaimsMap>
</JwtAuthHandlerConfig>
 * 
 */
public class JwtAuthHandler extends AbstractHandler implements ManagedLifecycle {

  private Log log = LogFactory.getLog(getClass());

  private String configKey;
  
  private String jwtHeaderName;

  private JwtValidator jwtValidator;
  
  private JwtDecryptor jwtDecryptor;
  
  private JwtClaimsMap jwtClaimsMap;
  
  private OMElement config;

  public static final String jwtValidatorRootConfigKey = "JwtAuthHandlerConfig";

  @Override
  public void destroy() {
    // Nothing to clean up
  }

  @Override
  public void init(SynapseEnvironment synapseEnvironment) {
    log.debug("Initializing with configKey = " + getConfigKey());
    if (getConfigKey() == null) {
      throw new SynapseException("Configuration key required but not specified!");
    }
    
    Registry reg = synapseEnvironment.getSynapseConfiguration().getRegistry();

    if (reg == null) {
      throw new SynapseException("Registry is null");
    }
    
    config = (OMElement) reg.lookup(getConfigKey());
    
    if (config.getLocalName() != jwtValidatorRootConfigKey) {
		throw new SynapseException(
	            "Initialization XML root element " + config.getLocalName()
	            + " doesn't match expected value " + jwtValidatorRootConfigKey + "!");
    }
    
    jwtHeaderName = Utils.GetElement("JwtHttpHeader", config).getText();
    
    jwtValidator = new JwtValidator(config);
    
    jwtClaimsMap = new JwtClaimsMap(Utils.GetElement("JwtClaimsMap", config));
    		
    log.debug("Initialization Complete");
  }

  /**
   * Checks if the request comes with a valid JWT from the API Manager.
   * 
   * @param messageContext
   *          MessageContext of the request
   */
  @Override
  public boolean handleRequest(MessageContext messageContext) {
     org.apache.axis2.context.MessageContext axis2MessageContext = 
        ((Axis2MessageContext) messageContext).getAxis2MessageContext();
     Map headersMap = (Map) axis2MessageContext
        .getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);
    
     if (headersMap == null) {
        // Return an HTTP internal server error to the client.
        sendResponse(HttpURLConnection.HTTP_INTERNAL_ERROR, headersMap, axis2MessageContext,
            messageContext, "No headers found");
        return false;
        }
  
      String jwtString = (String) headersMap.get(jwtHeaderName);
      
      if (jwtString == null || jwtString.isEmpty()) {
        if (log.isDebugEnabled()) {
          log.debug("JWT token not found, HTTP header "
              + jwtHeaderName + " is missing!");          
        }
        sendResponse(HttpURLConnection.HTTP_UNAUTHORIZED, headersMap, axis2MessageContext,
            messageContext, "JWT token not found, HTTP header " + jwtHeaderName + " not found");
        return false;
      }
      
      JWT jwt = null;
      try {
    	  
    	  String jwtConfigType = Utils.GetElementAttributeValue("JwtType", config);
    	  switch (jwtConfigType) {
    	  case "plain":
    		  jwt = PlainJWT.parse(jwtString);
    		  break;
    	  case "signed":
    		  jwt = SignedJWT.parse(jwtString);
    		  if (!jwtValidator.isValidJwt((SignedJWT)jwt)) {
    	          sendResponse(HttpURLConnection.HTTP_FORBIDDEN, headersMap, axis2MessageContext,
    	              messageContext, "JWT signature validation failed");
    	          return false;
    	      }
    	  case "encrypted":
    		  jwt = EncryptedJWT.parse(jwtString);
    		  jwtDecryptor.Decrypt((EncryptedJWT)jwt);
    		  
    		  break;
    	  }
    	  
      } catch (ParseException e) {
      }
      
      try {
    	  jwtClaimsMap.MapClaims(messageContext, jwt.getJWTClaimsSet());
      }
      catch (Exception e) {
          sendResponse(HttpURLConnection.HTTP_FORBIDDEN, headersMap, axis2MessageContext,
	              messageContext, e.getMessage());
	          return false;
      }
      
    return true;
  }

  private void sendResponse(int httpReturnCode, Map headersMap,
      org.apache.axis2.context.MessageContext axis2MessageContext, MessageContext messageContext, String failureReason) {
    headersMap.clear();
    if (httpReturnCode == HttpURLConnection.HTTP_UNAUTHORIZED) {
      // this HTTP header is required when 401 is returned
      headersMap.put("WWW-Authenticate", "jwt");
    }
    if (failureReason != null) {
    	headersMap.put("FailureReason", failureReason);
    }
    axis2MessageContext.setProperty("HTTP_SC", httpReturnCode);
    axis2MessageContext.setProperty("NO_ENTITY_BODY", Boolean.TRUE);
    messageContext.setProperty("RESPONSE", "true");
    messageContext.setTo(null);
    Axis2Sender.sendBack(messageContext);
  }

  @Override
  public boolean handleResponse(MessageContext messageContext) {
    // Ignore response
    return true;
  }

  // Below only getters and setters

  public String getConfigKey() {
    return configKey;
  }

  public void setConfigKey(String configKey) {
    this.configKey = configKey;
  }

}
