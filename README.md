## Introduction
Implements a WSO2 ESB security handler as described in https://docs.wso2.com/display/ESB490/Securing+APIs. For more examples, see also:
 - https://docs.wso2.com/display/AM200/Writing+Custom+Handlers
 - https://github.com/wso2/carbon-appmgt/blob/master/components/org.wso2.carbon.appmgt.gateway/src/main/java/org/wso2/carbon/appmgt/gateway/handlers/throttling/APIThrottleHandler.java  
 
Expects a JWT from the WSO2 API Manager as input with each request (see also: https://docs.wso2.com/display/AM210/Passing+Enduser+Attributes+to+the+Backend+Using+JWT). Only allows requests to pass if:
1.  the JWT is signed by the WSO2 API Manager
2.  the value of the issuer claim from the WSO2 API Manager matches with a configurable value

## Installation
Build the .jar file with maven (from the directory where the pom.xml file is located):
```sh
mvn package
```

Copy the resulting jar file to repository/components/lib and restart the ESB.

## Usage
Add the following section at the bottom of your `<api></api>` config:
```xml
<handlers>
  <handler class="be.i8c.wso2.esb.JwtAuthHandler">
    <property name="configKey" value="key of the configuration file in the Configuration repository of the ESB registry"/>
  </handler>
</handlers>
```
  
The configuration file referred to by the configKey should have the below structure and content. All elements are required.
  
```xml
<JwtAuthHandlerConfig>
  <Aliases>comma separated list of aliases to check the JWT signature against</Aliases>
  <JwtHttpHeader>HTTP header of the JWT token; default = X-JWT-Assertion</JwtHttpHeader>
  <JwtIssuer>value to check the issuer claim against; default = wso2.org/products/am</JwtIssuer>
  <KeystoreFilename>full filename (including path) of the Java Keystore that contains the aliases referred to by the Aliases element</KeystoreFilename>
  <KeystorePassword>password of the Java Keystore file referred to by the KeystoreFilename element</KeystorePassword>
</JwtAuthHandlerConfig>
```
  
  
## Example
### Configuration
The sample API below can be used to test the handler with the WSO2 ESB (edit via the source view of the ESB API Source editor:
```xml
<api xmlns="http://ws.apache.org/ns/synapse" context="/test" name="test">
	<resource methods="GET" url-mapping="/test">
		<inSequence>
			<payloadFactory media-type="json">
				<format>{"result":"ok"}</format>
				<args/>
			</payloadFactory>
			<loopback/>
		</inSequence>
	</resource>
        <handlers>
            <handler class="be.i8c.wso2.esb.JwtAuthHandler">
                <property name="configKey" value="conf:/repository/components/be.i8c.wso2.esb/JwtAuthHandlerConfig.xml"/>
            </handler>
        </handlers>
</api>
```
  
The sample configuration file below should be stored in the WSO2 ESB Registry at the location `/_system/config/repository/components/be.i8c.wso2.esb/JwtAuthHandlerConfig.xml`:
  
```xml
<JwtAuthHandlerConfig>
  <Aliases>wso2carbonQA,wso2carbonPROD</Aliases>
  <JwtHttpHeader>X-JWT-Assertion</JwtHttpHeader>
  <JwtIssuer>wso2.org/products/am</JwtIssuer>
  <KeystoreFilename>/opt/wso2/wso2am-2.1.0-update8/repository/resources/security/wso2carbon.jks</KeystoreFilename>
  <KeystorePassword>wso2carbon</KeystorePassword>
</JwtAuthHandlerConfig>
```
  
  
### Test
Call the API directly on the ESB, you should receive an unauthorized exception:
```sh
curl -iv -X GET --header 'Accept: application/json'  'http://localhost:8284/test/test'
```
Call the API directly on the ESB with an invalid JWT header, you should receive a forbidden exception:
```sh
curl -iv -X GET --header 'Accept: application/json' --header 'X-JWT-Assertion: test123' 'http://localhost:8284/test/test'
```
Call the API via the WSO2 API Manager with a valid token, you should receive a response = `{"result":"ok"}`: 
```sh
curl -X GET --header 'Accept: application/json' --header 'Authorization: Bearer b27463b5-f8bc-305d-a869-67257b27db00' 'http://localhost:8286/test/v1.0/test'
```
  
  
## Known Issues and Troubleshooting
1.  When the ESB restarts and the handler contains errors, the handler config will be removed from any existing API definitions.  
2.  You can check the certificates in the ESB and API Manager keystores with the following command:  
    
    ```sh
    keytool  -list -storepass wso2carbon -v -keystore ./repository/resources/security/wso2carbon.jks  
    ```
3.  Set the log level to DEBUG for the following loggers on the WSO2 ESB to see the debug messages in the log files:
    - be.i8c.wso2.esb.JwtAuthHandler
    - be.i8c.wso2.esb.JwtValidator
    - org.apache.synapse.transport.http.headers
    - org.apache.synapse.transport.http.wire
    