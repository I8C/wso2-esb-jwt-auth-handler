## Introduction
This JWT Handler is designed to be integrated into APIs exposed via Enterprise Integrator, allowing EI to validate that a request includes a JWT that is signed by an accepted authority before processing a given request. Any request that either does not include a signed JWT or that includes a JWT that is not signed by an approved authority will be refused before being processed.

See the following for more information on auth handlers in EI: https://docs.wso2.com/display/EI650/Applying+Security+to+an+API

 Only allows requests to pass if:
1.  the JWT is signed by the WSO2 API Manager
2.  the value of the issuer claim from the WSO2 API Manager matches with a configurable value

## Installation
Build the .jar file with maven (from the directory where the pom.xml file is located):
```sh
mvn package
```

Copy the resulting jar file to repository/components/lib and restart the EI.

## Usage
Add the following section at the bottom of your `<api></api>` config:
```xml
<handlers>
  <handler class="com.roblox.rcs.JwtAuthHandler">
    <property name="configKey" value="the file name in the conf folder containing the configuratiodn"/>
  </handler>
</handlers>
```
  
The configuration file referred to by the configKey should have the below structure and content. JwtClaimsMap may include elements listed as required and the mapped properties will be included and available in the APIs within the $ctx: context, it is possible to have no mappings. All other elements are required.
  
```xml
<JwtAuthHandlerConfig JwtType="signed">
  <Keystores>
    <Keystore KeystoreVaultKey="wso2carbon" CertificateAlias="wso2carbon">
      <Location>C:\Program Files\WSO2\wso2ei-6.5.0\repository\resources\security\wso2carbon.jks</Location>
      <Aliases>
        <Alias>wso2carbon</Alias>
      </Aliases>
    </Keystore>
  </Keystores>
  <JwtHttpHeader>X-JWT-Assertion</JwtHttpHeader>
  <JwtIssuer>wso2.org/products/am</JwtIssuer>
  <JwtClaimsMap>
    <Map>
      <JwtClaim>http://wso2.org/claims/subscriber</JwtClaim>
      <ContextProperty>JwtUsername</ContextProperty>
      <Required>true</Required>
    </Map>
      <Map>
      <JwtClaim>http://wso2.org/claims/role</JwtClaim>
      <ContextProperty>JwtRoles</ContextProperty>
      <Required>true</Required>
    </Map>
    <Map>
      <JwtClaim>exp</JwtClaim>
      <ContextProperty>JwtExpires</ContextProperty>
      <Required>true</Required>
      <DateValidationSeconds Past="0" Future="1800" />
    </Map>
  </JwtClaimsMap>
</JwtAuthHandlerConfig>
```
  
In the above example, EI will
1. Search for a JWT in the "X-JWT-Assertion" header as specified in the JwtAuthHandlerConfig/JwtHttpHeader element
2. Validate that a given JWT is encrypted by the specified certificate's private key and can be decrypted by the associated public key located in keystore within the Keystore element, with the associated alias as listed in the PrivateKeyVaultKey attribute.
3. Will scan the validated/decrypted JWT for attributes listed in the JwtClaimsMap. Mappings in which Required:true will be validated as present, and the JWT will be rejected if missing. Mapped attributes present in the JWT will be mapped to $ctx: variables as specified in the ContextProperty element. Example: The claim "http://wso2.org/claims/subscriber" is required and when found, it's value will be included in the $ctx:username variable within the executing API's context.

###Note
This is a heavily modified fork of the handler available here: https://github.com/I8C/wso2-esb-jwt-auth-handler