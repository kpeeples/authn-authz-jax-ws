package webservice.jaxws.client;
 
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.StringReader;
import java.net.URL;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;
 
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.Service;
 
import org.jboss.ws.core.StubExt;
import org.picketlink.identity.federation.api.wstrust.WSTrustClient.SecurityInfo;
import org.picketlink.identity.federation.api.wstrust.WSTrustClient;
import org.picketlink.identity.federation.core.wstrust.SamlCredential;
import org.picketlink.identity.federation.core.wstrust.plugins.saml.SAMLUtil;
import org.picketlink.trust.jbossws.SAML2Constants;

import webservice.jaxws.server.WSTest;

public class STSWSClient {
    
    public static void main(String[] args) throws Exception {

    	Element assertion = null;
   		try {
   			WSTrustClient client = new WSTrustClient("PicketLinkSTS", "PicketLinkSTSPort","http://localhost:8080/picketlink-sts/PicketLinkSTS",new SecurityInfo("UserA", "PassA"));
   			System.out.println("STSWSClient :: Invoking token service to get SAML assertion for UserA");
   			assertion = client.issueToken(SAMLUtil.SAML2_TOKEN_TYPE);
   			System.out.println("STSWSClient :: SAML assertion for UserA successfully obtained!");
   			SamlCredential credential = new SamlCredential(assertion);
   			//System.out.println("STSWSClient :: Assertion from issueToken unformatted");
   			//System.out.println(credential.getAssertionAsString());
   			System.out.println("STSWSClient :: Assertion from issueToken formatted");
   			printDocument(credential.getAssertionAsString(), System.out);
   			System.out.println("STSWSClient :: End Assertion from issueToken");
   		} catch (Exception wse) {
   			System.out.println("STSWSClient :: Unable to issue assertion: " + wse.getMessage());
   			wse.printStackTrace();
   		}
   		System.out.println("STSWSClient :: get wsdl");
    	   URL wsdl = new URL("http://localhost:8080/sampleDomain/SecureEndpoint?wsdl");
    	   System.out.println("STSWSClient :: setup servicename");
    	   QName serviceName = new QName("http://server.jaxws.webservice/", "WSTestBeanService");
    	   System.out.println("STSWSClient :: setup service");
    	   Service service = Service.create(wsdl, serviceName);
    	   System.out.println("STSWSClient :: call get port");
    	   WSTest port = service.getPort(new QName("http://server.jaxws.webservice/", "WSTestBeanPort"), WSTest.class);
    	   System.out.println("STSWSClient :: client handler");
   			/*URL wsdl = new URL("http://localhost:8080/wstest/WSTestBean?wsdl");
   			QName serviceName = new QName("http://test.webservice/", "WSTestBeanService");
   			Service service = Service.create(wsdl, serviceName);
   			WSTest port = service.getPort(new QName("http://test.webservice/", "WSTestBeanPort"), WSTest.class);*/
    	   ((StubExt) port).setConfigName("SAML WSSecurity Client"); 
    	   System.out.println("STSWSClient :: request context");
    	   ((BindingProvider) port).getRequestContext().put(SAML2Constants.SAML2_ASSERTION_PROPERTY, assertion);
    	   System.out.println("STSWSClient :: call echo");
    	   port.echo("Test");
    	   System.out.println("MAIN :: Complete");
    }
    public static void printDocument(String xmlString, OutputStream out) throws IOException, TransformerException {
	        TransformerFactory tf = TransformerFactory.newInstance();
	        Transformer transformer = tf.newTransformer();
			transformer.setOutputProperty(OutputKeys.INDENT, "yes");  
			transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
			transformer.setOutputProperty(OutputKeys.METHOD, "xml");
			transformer.setOutputProperty(OutputKeys.INDENT, "yes");
			transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
			transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			try
			{
			DocumentBuilder builder = factory.newDocumentBuilder();
			Document document = builder.parse(new InputSource(new StringReader(xmlString)));    
			transformer.transform(new DOMSource(document), new StreamResult(new OutputStreamWriter(System.out, "UTF-8")));
			}
			catch (Exception e)
			{
				 e.printStackTrace();
			}
    }
}