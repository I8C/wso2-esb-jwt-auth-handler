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

import static org.hamcrest.CoreMatchers.containsString;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.KeyStoreException;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMNode;
import org.apache.axiom.om.OMXMLBuilderFactory;
import org.apache.synapse.SynapseException;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class JwtValidatorTest {

  private static final String validjwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IlVCX0JReTJIR"
      + "lYzRU1UZ3E2NFEtMVZpdFliRSJ9.eyJodHRwOlwvXC93c28yLm9yZ1wvY2xhaW1zXC9yb2xlIjpbIkludGVybmFsXC"
      + "9zdWJzY3JpYmVyIiwiSW50ZXJuYWxcL2NyZWF0b3IiLCJBcHBsaWNhdGlvblwvYWRtaW5fRGVmYXVsdEFwcGxpY2F0"
      + "aW9uX1BST0RVQ1RJT04iLCJJbnRlcm5hbFwvcHVibGlzaGVyIiwiSW50ZXJuYWxcL2V2ZXJ5b25lIiwiYWRtaW4iXS"
      + "wiaHR0cDpcL1wvd3NvMi5vcmdcL2NsYWltc1wvYXBwbGljYXRpb250aWVyIjoiVW5saW1pdGVkIiwiaHR0cDpcL1wv"
      + "d3NvMi5vcmdcL2NsYWltc1wva2V5dHlwZSI6IlBST0RVQ1RJT04iLCJodHRwOlwvXC93c28yLm9yZ1wvY2xhaW1zXC"
      + "92ZXJzaW9uIjoidjEuMCIsImlzcyI6IndzbzIub3JnXC9wcm9kdWN0c1wvYW0iLCJodHRwOlwvXC93c28yLm9yZ1wv"
      + "Y2xhaW1zXC9hcHBsaWNhdGlvbm5hbWUiOiJEZWZhdWx0QXBwbGljYXRpb24iLCJodHRwOlwvXC93c28yLm9yZ1wvY2"
      + "xhaW1zXC9lbmR1c2VyIjoiYWRtaW5AY2FyYm9uLnN1cGVyIiwiaHR0cDpcL1wvd3NvMi5vcmdcL2NsYWltc1wvZW5k"
      + "dXNlclRlbmFudElkIjoiLTEyMzQiLCJodHRwOlwvXC93c28yLm9yZ1wvY2xhaW1zXC9zdWJzY3JpYmVyIjoiYWRtaW"
      + "4iLCJodHRwOlwvXC93c28yLm9yZ1wvY2xhaW1zXC90aWVyIjoiVW5saW1pdGVkIiwiaHR0cDpcL1wvd3NvMi5vcmdc"
      + "L2NsYWltc1wvYXBwbGljYXRpb25pZCI6IjEiLCJodHRwOlwvXC93c28yLm9yZ1wvY2xhaW1zXC91c2VydHlwZSI6Ik"
      + "FQUExJQ0FUSU9OIiwiZXhwIjoxNTE3NDk4MTEwLCJodHRwOlwvXC93c28yLm9yZ1wvY2xhaW1zXC9hcGljb250ZXh0"
      + "IjoiXC90ZXN0XC92MS4wIn0=.BMda2uLqLXPROKCwGHrPPAAN2YzWyTgaVkitLXpb920TeUKyFoz++2mBpAcx5rPrX"
      + "Ahd9yXP22TX+TFlWsVwGJv+SSt8Gic1gukaMnJLOtasc2ff8xGeMixwXOqp3s5a7B29jvX+/l9t8MYQzWqTGjKTcRU"
      + "Jk9KX9wsNVO1mZPahDRLX/OWHIvawI7EfunmDfj5J+kUxeQMc6vuYCe9sA0jow9rEXffOfzyDYvM4UuPmkLMHBjCM5"
      + "e69Ye9FtB0nH6FbSRN/d9lc5aVEkahOs69ORMi7yD66PgG6VkgFDUJttnBgS4s94jArKM1zzyKk+vcNjAt/QuaDx/z"
      + "edMCltA==";
  
  
  
  private OMElement goodConfig;
 
  @Before
  public void initialize() throws FileNotFoundException {
    goodConfig = OMXMLBuilderFactory.createOMBuilder(
        new FileInputStream("src/test/resources/GoodConfig.xml")).getDocumentElement();
  }
  
  @Test
  public void testIsValidJwtWithValidConfig() throws KeyStoreException {
	  /*
    JwtValidator jwtValidator = new JwtValidator(goodConfig);

    // test with valid token
    assertTrue(jwtValidator.isValidJwt(validjwt));
    // test with messed up token
    assertFalse(jwtValidator.isValidJwt(validjwt.substring(2)));

    
    // test with tampered claims in payload: changed iss from "wso2.org/products/am"
    // to "wso2.org/products/is"
    String[] validjwtparts = validjwt.split("\\.");
    validjwtparts[1] = "eyJodHRwOlwvXC93c28yLm9yZ1wvY2xhaW1zXC9yb2xlIjpbIkludGVybmFsXC9zdWJzY3JpYmVyIiwiSW50ZXJuYWxcL2NyZWF0b3IiLCJBcHBsaWNhdGlvblwvYWRtaW5fRGVmYXVsdEFwcGxpY2F0aW9uX1BST0RVQ1RJT04iLCJJbnRlcm5hbFwvcHVibGlzaGVyIiwiSW50ZXJuYWxcL2V2ZXJ5b25lIiwiYWRtaW4iXSwiaHR0cDpcL1wvd3NvMi5vcmdcL2NsYWltc1wvYXBwbGljYXRpb250aWVyIjoiVW5saW1pdGVkIiwiaHR0cDpcL1wvd3NvMi5vcmdcL2NsYWltc1wva2V5dHlwZSI6IlBST0RVQ1RJT04iLCJodHRwOlwvXC93c28yLm9yZ1wvY2xhaW1zXC92ZXJzaW9uIjoidjEuMCIsImlzcyI6IndzbzIub3JnXC9wcm9kdWN0c1wvaXMiLCJodHRwOlwvXC93c28yLm9yZ1wvY2xhaW1zXC9hcHBsaWNhdGlvbm5hbWUiOiJEZWZhdWx0QXBwbGljYXRpb24iLCJodHRwOlwvXC93c28yLm9yZ1wvY2xhaW1zXC9lbmR1c2VyIjoiYWRtaW5AY2FyYm9uLnN1cGVyIiwiaHR0cDpcL1wvd3NvMi5vcmdcL2NsYWltc1wvZW5kdXNlclRlbmFudElkIjoiLTEyMzQiLCJodHRwOlwvXC93c28yLm9yZ1wvY2xhaW1zXC9zdWJzY3JpYmVyIjoiYWRtaW4iLCJodHRwOlwvXC93c28yLm9yZ1wvY2xhaW1zXC90aWVyIjoiVW5saW1pdGVkIiwiaHR0cDpcL1wvd3NvMi5vcmdcL2NsYWltc1wvYXBwbGljYXRpb25pZCI6IjEiLCJodHRwOlwvXC93c28yLm9yZ1wvY2xhaW1zXC91c2VydHlwZSI6IkFQUExJQ0FUSU9OIiwiZXhwIjoxNTE3NDk4MTEwLCJodHRwOlwvXC93c28yLm9yZ1wvY2xhaW1zXC9hcGljb250ZXh0IjoiXC90ZXN0XC92MS4wIn0=";
    assertFalse(jwtValidator.isValidJwt(validjwtparts[0]+"."+validjwtparts[1]+"."+validjwtparts[2]));
    
    // test with tampered header: changed alg from "RS256" to "XXX"
    validjwtparts = validjwt.split("\\.");
    validjwtparts[0] = "eyJ0eXAiOiJKV1QiLCJhbGciOiJYWFgiLCJ4NXQiOiJVQl9CUXkySEZWM0VNVGdxNjRRLTFWaXRZYkUifQ==";
    assertFalse(jwtValidator.isValidJwt(validjwtparts[0]+"."+validjwtparts[1]+"."+validjwtparts[2]));
  }
  
  @Rule
  public ExpectedException thrown = ExpectedException.none();
  
  @Test
  public void testConstructorWithInputParameterNull()  {
    thrown.expect(SynapseException.class);
    thrown.expectMessage("Initialization XML should not be null!");
    new JwtValidator(null);
  }

  @Test
  public void testConstructorWithAdditionalConfig() throws FileNotFoundException,
      KeyStoreException {
    OMElement additionalConfig = OMXMLBuilderFactory.createOMBuilder(
        new FileInputStream("src/test/resources/AdditionalElementConfig.xml"))
        .getDocumentElement();
    assertTrue((new JwtValidator(additionalConfig)).isValidJwt(validjwt));
  }
  
  @Test
  public void testConstructorWithInvalidRootXmlElement() throws FileNotFoundException {
    OMElement badConfig = OMXMLBuilderFactory.createOMBuilder(
        new FileInputStream("src/test/resources/InvalidRootElementConfig.xml"))
        .getDocumentElement();
    thrown.expect(SynapseException.class);    
    thrown.expectMessage(containsString("doesn't match expected value"));
    new JwtValidator(badConfig);
  }

  @Test
  public void testConstructorWithEmptyConfig() throws FileNotFoundException {
    OMNode badConfig = OMXMLBuilderFactory.createOMBuilder(
        new FileInputStream("src/test/resources/EmptyConfig.xml"))
        .getDocument().getFirstOMChild();
    thrown.expect(SynapseException.class);    
    thrown.expectMessage("Initialization XML doesn't seem to contain a root element!");
    new JwtValidator(badConfig);
  }
  
  @Test
  public void testConstructorWithEmptyKeystoreFilenameConfig() throws FileNotFoundException {
    OMElement badConfig = OMXMLBuilderFactory.createOMBuilder(
        new FileInputStream("src/test/resources/EmptyKeystoreFilenameConfig.xml"))
        .getDocumentElement();
    thrown.expect(SynapseException.class);    
    thrown.expectMessage(containsString("should contain the path to a valid .jks file!"));
    new JwtValidator(badConfig);
  }
  
  @Test
  public void testConstructorWithEmptyAliasesConfig() throws FileNotFoundException {
    OMElement badConfig = OMXMLBuilderFactory.createOMBuilder(
        new FileInputStream("src/test/resources/EmptyAliasesConfig.xml"))
        .getDocumentElement();
    thrown.expect(SynapseException.class);    
    thrown.expectMessage(containsString("comma separated list of certificate aliases"));
    new JwtValidator(badConfig);
  }
  
  @Test
  public void testConstructorWithEmptyKeystorePasswordConfig() throws FileNotFoundException {
    OMElement badConfig = OMXMLBuilderFactory.createOMBuilder(
        new FileInputStream("src/test/resources/EmptyKeystorePasswordConfig.xml"))
        .getDocumentElement();
    thrown.expect(SynapseException.class);    
    thrown.expectMessage(containsString("should contain the password of the file"));
    new JwtValidator(badConfig);
  }
  
  @Test
  public void testConstructorWithEmptyJwtIssuerConfig() throws FileNotFoundException {
    OMElement badConfig = OMXMLBuilderFactory.createOMBuilder(
        new FileInputStream("src/test/resources/EmptyJwtIssuerConfig.xml"))
        .getDocumentElement();
    thrown.expect(SynapseException.class);    
    thrown.expectMessage(containsString("should contain the value of the issuer claim"));
    new JwtValidator(badConfig);
  }
  
  @Test
  public void testConstructorWithEmptyJwtHttpHeaderConfig() throws FileNotFoundException {
    OMElement badConfig = OMXMLBuilderFactory.createOMBuilder(
        new FileInputStream("src/test/resources/EmptyJwtHttpHeaderConfig.xml"))
        .getDocumentElement();
    thrown.expect(SynapseException.class);    
    thrown.expectMessage(containsString("defaults to X-JWT-Assertion"));
    new JwtValidator(badConfig);
  }
  
  @Test
  public void testUnexistingKeystoreFilename() throws FileNotFoundException, KeyStoreException  {
    OMElement badConfig = OMXMLBuilderFactory.createOMBuilder(
        new FileInputStream("src/test/resources/UnexistingKeystoreFilenameConfig.xml"))
        .getDocumentElement();
    thrown.expect(SynapseException.class);
    new JwtValidator(badConfig);
  }
  
  @Test
  public void testInvalidKeystoreFilename() throws FileNotFoundException, KeyStoreException {
    OMElement badConfig = OMXMLBuilderFactory.createOMBuilder(
        new FileInputStream("src/test/resources/InvalidKeystoreFilenameConfig.xml"))
        .getDocumentElement();
    thrown.expect(SynapseException.class);
    new JwtValidator(badConfig);
  }

  
  @Test
  public void testInvalidAlias() throws KeyStoreException {
    JwtValidator jwtValidator = new JwtValidator(goodConfig);
    jwtValidator.setAliases("wrongalias");
    
    assertFalse(jwtValidator.isValidJwt(validjwt));

    jwtValidator.setAliases(null);
    assertFalse(jwtValidator.isValidJwt(validjwt));
  }

  @Test
  public void testInvalidSignature() throws KeyStoreException {
    JwtValidator jwtValidator = new JwtValidator(goodConfig);
    jwtValidator.setAliases("equifaxsecureebusinessca2");

    assertFalse(jwtValidator.isValidJwt(validjwt));
  }

  @Test
  public void testInvalidIssuer() throws KeyStoreException {
    JwtValidator jwtValidator = new JwtValidator(goodConfig);
    jwtValidator.setJwtIssuer("wrongIssuer");

    assertFalse(jwtValidator.isValidJwt(validjwt));
    */
  }

}
