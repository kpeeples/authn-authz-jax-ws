package mil.spawar.esf2.jaxws.client;
 
import java.net.URL;
 
import org.w3c.dom.Element;
 
import javax.xml.namespace.QName;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.Service;
 
import org.jboss.ws.core.StubExt;
import org.picketlink.identity.federation.api.wstrust.WSTrustClient.SecurityInfo;
import org.picketlink.identity.federation.api.wstrust.WSTrustClient;
import org.picketlink.identity.federation.core.wstrust.SamlCredential;
import org.picketlink.identity.federation.core.wstrust.WSTrustException;
import org.picketlink.identity.federation.core.wstrust.plugins.saml.SAMLUtil;
import org.picketlink.trust.jbossws.SAML2Constants;
import org.w3c.dom.Element;
import webservice.test.*;
 
import mil.spawar.esf2.jaxws.server.*;

public class STSWSClient {
    
    public static void main(String[] args) throws Exception {

    	   Element assertion = null;
    	   SamlForHandler sfh = new SamlForHandler();
    	   assertion = sfh.issue("UserA", "PassA");
    	   //URL wsdl = new URL("http://esf2:8180/wstest/WSTestBean?wsdl");
    	   URL wsdl = new URL("http://esf2:8180/sampleDomain/SecureEndpoint?wsdl");
    	   QName serviceName = new QName("http://test.webservice/", "WSTestBeanService");
    	   Service service = Service.create(wsdl, serviceName);
    	   WSTest port = service.getPort(new QName("http://test.webservice/", "WSTestBeanPort"), WSTest.class);
    	   ((StubExt) port).setConfigName("SAML WSSecurity Client"); 
    	   ((BindingProvider) port).getRequestContext().put(SAML2Constants.SAML2_ASSERTION_PROPERTY, assertion);
    	   port.echo("Test");
    	   System.out.println("MAIN :: Complete");
    }
 
}