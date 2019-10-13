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

import java.util.Map;

import javax.xml.stream.XMLStreamException;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.text.ParseException;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMDocument;
import org.apache.axiom.om.impl.builder.StAXOMBuilder;
import org.apache.commons.httpclient.util.HttpURLConnection;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.commons.io.FileUtils;
import org.apache.synapse.ManagedLifecycle;
import org.apache.synapse.MessageContext;
import org.apache.synapse.SynapseException;
import org.apache.synapse.core.SynapseEnvironment;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.core.axis2.Axis2Sender;
import org.apache.synapse.config.SynapseConfigUtils;
import org.apache.synapse.registry.Registry;
import org.apache.synapse.rest.AbstractHandler;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.EncryptedJWT;

import com.roblox.rcs.JwtDecryptor;
import com.roblox.rcs.JwtClaimsMap;

import com.roblox.rcs.Utils;

public class JwtAuthHandler extends AbstractHandler implements ManagedLifecycle {

	public static final String CARBON_CONFIG_DIR_PATH = "carbon.config.dir.path";
	public static final String CARBON_SERVICEPACKS_DIR_PATH = "carbon.servicepacks.dir.path";
	public static final String CARBON_DROPINS_DIR_PATH = "carbon.dropins.dir.path";
	public static final String CARBON_EXTERNAL_LIB_DIR_PATH = "carbon.external.lib.dir.path"; // components/lib
	public static final String CARBON_EXTENSIONS_DIR_PATH = "carbon.extensions.dir.path";
	public static final String CARBON_COMPONENTS_DIR_PATH= "carbon.components.dir.path";
	public static final String CARBON_PATCHES_DIR_PATH = "carbon.patches.dir.path";
	public static final String CARBON_INTERNAL_LIB_DIR_PATH = "carbon.internal.lib.dir.path"; //lib normally internal tomcat
	public static final String CARBON_CONFIG_DIR_PATH_ENV = "CARBON_CONFIG_DIR_PATH";
	public static final String CARBON_HOME = "carbon.home";
	public static final String CARBON_HOME_ENV = "CARBON_HOME";
	public static final String AXIS2_CONFIG_REPO_LOCATION = "Axis2Config.RepositoryLocation";

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
    log.info("Initializing with configKey = " + getConfigKey());
    if (getConfigKey() == null) {
      throw new SynapseException("Configuration key required but not specified!");
    }



    String configFilePath = getCarbonConfigDirPath() + File.separator + getConfigKey();

    log.info("Loading config file from path: " + configFilePath);

    InputStream configStream = null;
    try {
      configStream = FileUtils.openInputStream(new File(configFilePath));
    } catch (IOException e) {
      e.printStackTrace();
    }

    StAXOMBuilder builder = null;
    try {
      builder = new StAXOMBuilder(configStream);
    } catch (XMLStreamException e) {
      e.printStackTrace();
    }
    
    config = builder.getDocumentElement();
    
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


  // Blatently stolen from:L
  // core/org.wso2.carbon.base/src/main/java/org/wso2/carbon/base/CarbonBaseUtils.java
  public static String getCarbonConfigDirPath() {
		String carbonConfigDirPath = System
				.getProperty(CARBON_CONFIG_DIR_PATH);
		if (carbonConfigDirPath == null) {
			carbonConfigDirPath = System
					.getenv(CARBON_CONFIG_DIR_PATH_ENV);
			if (carbonConfigDirPath == null) {
				return getCarbonHome() + File.separator + "repository"
						+ File.separator + "conf";
			}
		}
		return carbonConfigDirPath;
  }
  
  public static String getCarbonHome() {
		String carbonHome = System.getProperty(CARBON_HOME);
		if (carbonHome == null) {
			carbonHome = System.getenv(CARBON_HOME_ENV);
			System.setProperty(CARBON_HOME, carbonHome);
		}
		return carbonHome;
	}

}
