package webservice.jaxws.handlers;

import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintStream;
import java.security.AccessController;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.security.acl.Group;
import java.util.ArrayList;
import java.util.List;
import javax.security.auth.Subject;
import javax.xml.namespace.QName;
import javax.xml.soap.SOAPMessage;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.SOAPMessageContext;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.jboss.security.SecurityConstants;
import org.jboss.security.SecurityContext;
import org.jboss.security.SecurityContextAssociation;
import org.jboss.security.SecurityContextFactory;
import org.jboss.security.SimplePrincipal;

import org.picketlink.identity.federation.bindings.jboss.subject.PicketLinkGroup;
import org.picketlink.identity.federation.bindings.jboss.subject.PicketLinkPrincipal;
import org.picketlink.identity.federation.core.ErrorCodes;
import org.picketlink.identity.federation.core.saml.v2.constants.JBossSAMLURIConstants;
import org.picketlink.identity.federation.core.saml.v2.util.AssertionUtil;
import org.picketlink.identity.federation.core.util.StringUtil;
import org.picketlink.identity.federation.core.wstrust.SamlCredential;
import org.picketlink.identity.federation.core.wstrust.plugins.saml.SAMLUtil;
import org.picketlink.identity.federation.saml.v2.assertion.AssertionType;
import org.picketlink.trust.jbossws.Util;
import org.picketlink.trust.jbossws.handler.AbstractPicketLinkTrustHandler;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;


public class SAML2ServerHandler extends AbstractPicketLinkTrustHandler
{ 
	public static final String ROLE_KEY_SYS_PROP = "picketlink.rolekey";

    protected boolean handleInbound(MessageContext mc)
    { 
  	  PrintStream out = System.out;
  	  Boolean outbound = (Boolean)mc.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY);
  	  if (outbound.booleanValue())
  	    out.println("SAML2ServerHandler :: Outbound message");
  	  else
  	    out.println("SAML2ServerHandler :: Inbound message");
 	  String assertionNS = JBossSAMLURIConstants.ASSERTION_NSURI.get();
       SOAPMessageContext ctx = (SOAPMessageContext) mc;
       SOAPMessage soapMessage = ctx.getMessage();
       if(soapMessage == null)
          throw new IllegalStateException("SAML2ServerHandler :: "+ErrorCodes.NULL_VALUE + "SOAP Message");
       Document document = soapMessage.getSOAPPart();
       try {
		printDocument(document, out);
       } catch (IOException | TransformerException e1) {
    	   e1.printStackTrace();
       }
       Element soapHeader = Util.findOrCreateSoapHeader(document.getDocumentElement());
       Element assertion = Util.findElement(soapHeader, new QName(assertionNS, "Assertion"));
       if (assertion != null)
       {
          AssertionType assertionType = null;
          try
          {
             assertionType = SAMLUtil.fromElement(assertion);
             if(AssertionUtil.hasExpired(assertionType))
                throw new RuntimeException("SAML2ServerHandler :: "+ErrorCodes.EXPIRED_ASSERTION + "Assertion has expired");
          }
          catch(Exception e )
          { 
             out.println("SAML2ServerHandler :: Exception in parsing the assertion: " +e.getMessage());
          }
          SamlCredential credential = new SamlCredential(assertion);
          out.println("SAML2ServerHandler :: Assertion included in SOAP payload");
          out.println("SAML2ServerHandler :: "+credential.getAssertionAsString());
          Element subject = Util.findElement(assertion, new QName(assertionNS, "Subject"));
          Element nameID = Util.findElement(subject, new QName(assertionNS, "NameID"));
          String username = getUsername(nameID);
          out.println("SAML2ServerHandler :: username-->"+username);
          // set SecurityContext
          Subject theSubject = new Subject();
          SecurityContext sc = SecurityActions.createSecurityContext(new PicketLinkPrincipal(username), credential, theSubject);
          SecurityActions.setSecurityContext(sc);
          if(assertionType != null )
          {
             List<String> roleKeys = new ArrayList<String>();
             String roleKey = SecurityActions.getSystemProperty( ROLE_KEY_SYS_PROP, "Role");
             if(StringUtil.isNotNull(roleKey))
             {
                roleKeys.addAll(StringUtil.tokenize(roleKey));
             }

             out.println("SAML2ServerHandler :: Rolekeys to extract roles from the assertion:" + roleKeys);
             List<String> roles = AssertionUtil.getRoles(assertionType, roleKeys); 
             if(roles.size() > 0 )
             {
                out.println("SAML2ServerHandler :: Roles in the assertion:" + roles);
                Group roleGroup = SecurityActions.group(roles);
                theSubject.getPrincipals().add(roleGroup); 
             }
             else
             {
                out.println("SAML2ServerHandler :: Did not find roles in the assertion");
             } 
          } 
       }
       else
       {
          out.println("SAML2ServerHandler :: We did not find any assertion");
       } 
       return true;
    }
   

   static SecurityContext createSecurityContext(final Principal p, final Object cred, final Subject subject)
   {
      return AccessController.doPrivileged(new PrivilegedAction<SecurityContext>()
      {
         public SecurityContext run()
         {
            SecurityContext sc = null;
            try
            {
               sc = SecurityContextFactory.createSecurityContext(p, cred, subject, "SAML2_HANDLER");
            }
            catch (Exception e)
            {
               throw new RuntimeException(e);
            }
            return sc;
         }
      });
   }

   static void setSecurityContext(final SecurityContext sc)
   {
      AccessController.doPrivileged(new PrivilegedAction<Object>()
      {
         public Object run()
         {
            SecurityContextAssociation.setSecurityContext(sc);
            return null;
         }
      });
   }
   
   static SecurityContext getSecurityContext()
   {
      return AccessController.doPrivileged(new PrivilegedAction<SecurityContext>()
      {
         public SecurityContext run()
         {
            return SecurityContextAssociation.getSecurityContext();
         }
      });
   }
   /**
    * Get the {@link Subject} from the {@link SecurityContextAssociation}
    * @return authenticated subject or null
    */
   static Subject getAuthenticatedSubject()
   {
      return AccessController.doPrivileged(new PrivilegedAction<Subject>()
      { 
         public Subject run()
         {
            SecurityContext sc = SecurityContextAssociation.getSecurityContext();
            if( sc != null )
               return sc.getUtil().getSubject();
            return null;
         }
      });
   }
   
   /**
    * Get a system property
    * @param key the property name
    * @param defaultValue default value in absence of property
    * @return
    */
   static String getSystemProperty( final String key, final String defaultValue)
   {
      return AccessController.doPrivileged(new PrivilegedAction<String>()
      { 
         public String run()
         {
            return System.getProperty(key, defaultValue);
         }
      });
   }
   
   static ClassLoader getClassLoader( final Class<?> clazz)
   {
      return AccessController.doPrivileged(new PrivilegedAction<ClassLoader>()
      { 
         public ClassLoader run()
         {
            return clazz.getClassLoader();
         }
      });
   }
   
   static ClassLoader getContextClassLoader()
   {
      return AccessController.doPrivileged(new PrivilegedAction<ClassLoader>()
      { 
         public ClassLoader run()
         {
            return Thread.currentThread().getContextClassLoader();
         }
      });
   }
   
   /**
    * Given a {@link List} of role names, construct a group principal of type {@link Group}
    * @param roles
    * @return
    */
   static Group group(final List<String> roles)
   {
      return AccessController.doPrivileged(new PrivilegedAction<Group>()
      {  
         public Group run()
         {
            Group theGroup = new PicketLinkGroup(SecurityConstants.ROLES_IDENTIFIER);
            for(String role: roles)
            {
               theGroup.addMember(new SimplePrincipal(role));
            }
            return theGroup;
         }
      });
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
   protected String  getUsername(final Element nameID) {
	           String username = nameID.getNodeValue();
	           if (username == null) {
	               final NodeList childNodes = nameID.getChildNodes();
	               final int size = childNodes.getLength();
	               for (int i = 0; i < size; i++) {
	                   final Node childNode = childNodes.item(i);
	                   if (childNode.getNodeType() == Node.TEXT_NODE) {
	                       username = childNode.getNodeValue();
	                   }
	               }
	           }
	           return username;
	       }
}