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

import java.security.KeyStoreException;
import java.util.Map;

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
 * should contain the following XML structure:
 * <JwtAuthHandlerConfig>
 *   <Aliases>wso2carbonQA,wso2carbonPROD</Aliases>
 *   <JwtHttpHeader>X-JWT-Assertion</JwtHttpHeader>
 *   <JwtIssuer>wso2.org/products/am</JwtIssuer>
 *   <KeystoreFilename>/opt/wso2/wso2am-2.1.0-update8/repository/resources/security/wso2carbon.jks</KeystoreFilename>
 *   <KeystorePassword>wso2carbon</KeystorePassword>
 * </JwtAuthHandlerConfig>
 * 
 */
public class JwtAuthHandler extends AbstractHandler implements ManagedLifecycle {

  private Log log = LogFactory.getLog(getClass());

  private String configKey;

  private JwtValidator jwtValidator;

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
    
    jwtValidator = new JwtValidator(reg.lookup(getConfigKey()));

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
    Object headers = axis2MessageContext
        .getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);

    if (headers != null && headers instanceof Map) {
      Map headersMap = (Map) headers;
      Object jwtObject = headersMap.get(jwtValidator.getJwtHttpHeader());
      if (jwtObject == null) {
        if (log.isDebugEnabled()) {
          log.debug("JWT token not found, HTTP header "
              + jwtValidator.getJwtHttpHeader() + " is missing!");          
        }
        sendResponse(HttpURLConnection.HTTP_UNAUTHORIZED, headersMap, axis2MessageContext,
            messageContext);
        return false;
      } else {
        String jwt = (String) jwtObject;
        try {
          if (jwtValidator.isValidJwt(jwt)) {
            return true;
          } else {
            sendResponse(HttpURLConnection.HTTP_FORBIDDEN, headersMap, axis2MessageContext,
                messageContext);
            return false;
          }
        } catch (KeyStoreException e) {
          log.error("Exception validating JWT: " + e.getMessage());
          // Add stack trace to log to simplify troubleshooting.
          for (StackTraceElement ste : e.getStackTrace()) {
            log.error(ste);
          }
          // Return an HTTP internal server error to the client.
          sendResponse(HttpURLConnection.HTTP_INTERNAL_ERROR, headersMap, axis2MessageContext,
              messageContext);
          return false;
        }
      }
    }
    return false;
  }

  private void sendResponse(int httpReturnCode, Map headersMap,
      org.apache.axis2.context.MessageContext axis2MessageContext, MessageContext messageContext) {
    headersMap.clear();
    if (httpReturnCode == HttpURLConnection.HTTP_UNAUTHORIZED) {
      // this HTTP header is required when 401 is returned
      headersMap.put("WWW-Authenticate", "jwt");
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
