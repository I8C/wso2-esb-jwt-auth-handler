package com.roblox.rcs;

import org.apache.axiom.om.xpath.DocumentNavigator;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMAttribute;
import org.wso2.securevault.secret.SecretManager;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.Properties;

public class Utils {
	
	public static String GetElementAttributeValue(String name, OMElement element) {
		DocumentNavigator nav = new DocumentNavigator();
		Iterator<OMAttribute> i = element.getAllAttributes();
        while (i.hasNext()) {
        	OMAttribute current = i.next();
        	if (nav.getAttributeName(current) == name) {
        		return nav.getAttributeStringValue(current);
        	}
        }
        return null;
	}
	
	public static OMElement GetElement(String name, OMElement element) {
		DocumentNavigator nav = new DocumentNavigator();
		Iterator<OMElement> i = element.getChildElements();
        while (i.hasNext()) {
        	OMElement current = i.next();
        	if (nav.getElementName(current) == name) {
        		return current;
        	}
        }
        return null;
	}
	
	public static String GetAttributeValue(String name, OMElement element) {
		DocumentNavigator nav = new DocumentNavigator();
		Iterator<OMAttribute> i = element.getAllAttributes();
        while (i.hasNext()) {
        	OMAttribute current = i.next();
        	if (nav.getAttributeName(current) == name) {
        		return nav.getAttributeStringValue(current);
        	}
        }
        return null;
	}
	
	public static int countChildren(OMElement element) {
		int cnt = 0;
		Iterator<OMElement> i = element.getChildElements();
        while (i.hasNext()) {
        	cnt++;
        	i.next();
        	}
        
        return cnt;
	}
	
	public static String GetVaultValue(String valueName) {
		SecretManager mgr = SecretManager.getInstance();
		mgr.init(new Properties());
		String secret = mgr.getSecret(valueName);
		
		// For test environments that don't have the keystore
		// configured, wso2carbon should work for basic scenarios
		if (secret == null) { return "wso2carbon"; }
		
		return mgr.getSecret(valueName);
	}
	
	public static ArrayList<String> GetChildElementValues(OMElement element) {
		ArrayList<String> toReturn = new ArrayList<String>();
		
		Iterator<OMElement> childs = element.getChildElements();
		while (childs.hasNext()) {
			toReturn.add(childs.next().getText());
		}
		
		return toReturn;
	}

}
