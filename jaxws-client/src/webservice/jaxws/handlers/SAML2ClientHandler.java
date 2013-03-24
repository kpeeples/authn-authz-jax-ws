package webservice.jaxws.handlers;

import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintStream;
import java.util.Set;
import javax.xml.namespace.QName;
import javax.xml.soap.SOAPMessage;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.SOAPMessageContext;

import org.picketlink.trust.jbossws.SAML2Constants;
import org.picketlink.trust.jbossws.Constants;
import org.picketlink.trust.jbossws.Util;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class SAML2ClientHandler implements javax.xml.ws.handler.soap.SOAPHandler<SOAPMessageContext> 
{
	 
    @Override
    public Set<QName> getHeaders() {
       return null;
    }

    @Override
    public void close(MessageContext mc) {
    }

    @Override
    public boolean handleFault(SOAPMessageContext mc) {
       return true;
    }

	@Override
    public boolean handleMessage(SOAPMessageContext mc) {
    	  PrintStream out = System.out;

    	  Boolean outbound = (Boolean)mc.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY);

    	  if (outbound.booleanValue())
    	    out.println("SAML2ClientHandler :: Outbound message");
    	  else
    	    out.println("SAML2ClientHandler :: Inbound message");
    	  SOAPMessageContext ctx = (SOAPMessageContext) mc;
    	  SOAPMessage message = mc.getMessage();
    	  if (ctx.get(SOAPMessageContext.WSDL_OPERATION) == null)
    	  {
    		  out.println("SAML2ClientHandler :: null WSDL_OPERATION returning");
    		  return true;
    	  }
    	  /*try {
			message.writeTo(out);
    	  } catch (SOAPException | IOException e) {
			e.printStackTrace();
    	  }*/
    	  out.println();
          out.println("SAML2ClientHandler :: WSDL_PORT=" + ctx.get(SOAPMessageContext.WSDL_PORT));
          out.println("SAML2ClientHandler :: WSDL_OPERATION=" + ctx.get(SOAPMessageContext.WSDL_OPERATION));
          out.println("SAML2ClientHandler :: WSDL_INTERFACE=" + ctx.get(SOAPMessageContext.WSDL_INTERFACE));
          out.println("SAML2ClientHandler :: WSDL_SERVICE=" + ctx.get(SOAPMessageContext.WSDL_SERVICE));
          Element assertion = (Element) ctx.get(SAML2Constants.SAML2_ASSERTION_PROPERTY);        
          if(assertion == null )
          {
             out.println("SAML2ClientHandler :: No Assertion was found on the message context. Returning.");
             return true;
          }
          
          // add wsse header
          Document document = message.getSOAPPart();
          Element soapHeader = Util.findOrCreateSoapHeader(document.getDocumentElement());
          try
          {
             Element wsse = document.createElementNS(Constants.WSSE_NS, Constants.WSSE_HEADER);
             Util.addNamespace(wsse, Constants.WSSE_PREFIX, Constants.WSSE_NS);
             Util.addNamespace(wsse, Constants.WSU_PREFIX, Constants.WSU_NS);
             Util.addNamespace(wsse, Constants.XML_ENCRYPTION_PREFIX, Constants.XML_SIGNATURE_NS);
             wsse.setAttributeNS(soapHeader.getNamespaceURI(), soapHeader.getPrefix() + ":mustUnderstand", "1");
             if (assertion != null)
             {
                // add the assertion as a child of the wsse header
                // check if the assertion element comes from the same document, otherwise import the node
                if (document != assertion.getOwnerDocument())
                {
                   wsse.appendChild(document.importNode(assertion, true));
                }
                else
                {
                   wsse.appendChild(assertion);
                }
             }
             soapHeader.insertBefore(wsse, soapHeader.getFirstChild());
             printDocument(document, out);
          }
          catch (Exception e)
          {
        	  e.printStackTrace();
             return false;
          }
    	  return true;
    	  
    	}
    public static void printDocument(Document doc, OutputStream out) throws IOException, TransformerException {
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer transformer = tf.newTransformer();
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
        transformer.setOutputProperty(OutputKeys.METHOD, "xml");
        transformer.setOutputProperty(OutputKeys.INDENT, "yes");
        transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
        transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");
        transformer.transform(new DOMSource(doc), new StreamResult(new OutputStreamWriter(out, "UTF-8")));
    }
}
