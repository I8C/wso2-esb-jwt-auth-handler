package com.roblox.rcs;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMNode;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.axis2.context.MessageContext;
import java.util.ArrayList;
import java.util.Iterator;

import com.nimbusds.jwt.JWTClaimsSet;

import com.roblox.rcs.JwtClaimMapping;

public class JwtClaimsMap {

	  private Log log = LogFactory.getLog(getClass());
	  
	  private ArrayList<JwtClaimMapping> claimsMap;
	  
	  public JwtClaimsMap(OMElement configClaims) {
		  claimsMap = new ArrayList<JwtClaimMapping>();
		  
		  Iterator<OMElement> i = configClaims.getChildElements();
		  while (i.hasNext()) {
			  OMElement mapElement = i.next();
			  JwtClaimMapping mapping = new JwtClaimMapping();
			  mapping.SourceClaim = Utils.GetElement("JwtClaim", mapElement).getText();
			  mapping.TargetProperty = Utils.GetElement("ContextProperty", mapElement).getText();
			  mapping.Required = Boolean.parseBoolean(Utils.GetElement("Required", mapElement).getText());
			  claimsMap.add(mapping);
		  }
	  }
	  
	  public void MapClaims(org.apache.synapse.MessageContext messageContext, JWTClaimsSet claims) throws Exception {
		  Iterator<JwtClaimMapping> Imapping = claimsMap.iterator();
		  while (Imapping.hasNext()) {
			  JwtClaimMapping mapping = Imapping.next();
			  Object claim = claims.getClaim(mapping.SourceClaim);
			  if (claim == null) {
				  if (mapping.Required) {
					  throw new Exception("Required claim \"" + mapping.SourceClaim + "\" not present");
				  }
				  continue;
			  }
			  messageContext.setProperty(mapping.TargetProperty, claim);
		  }
	  }
}
