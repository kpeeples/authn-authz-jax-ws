package mil.spawar.esf2.cap.jaxws.handlers;

import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.security.AccessController;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.security.acl.Group;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import javax.security.auth.Subject;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.soap.SOAPBody;
import javax.xml.soap.SOAPElement;
import javax.xml.soap.SOAPEnvelope;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPHeader;
import javax.xml.soap.SOAPMessage;
import javax.xml.soap.SOAPPart;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.SOAPMessageContext;
import javax.xml.transform.Result;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import mil.spawar.esf2.jaxws.client.SamlForHandler;  

import org.jboss.security.SecurityConstants;
import org.jboss.security.SecurityContext;
import org.jboss.security.SecurityContextAssociation;
import org.jboss.security.SecurityContextFactory;
import org.jboss.security.SimplePrincipal;
import org.jboss.ws.core.StubExt;

//TO DO add native core to pom and mark as provided

import org.picketlink.identity.federation.api.wstrust.WSTrustClient;
import org.picketlink.identity.federation.api.wstrust.WSTrustClient.SecurityInfo;
import org.picketlink.identity.federation.bindings.jboss.subject.PicketLinkGroup;
import org.picketlink.identity.federation.bindings.jboss.subject.PicketLinkPrincipal;
import org.picketlink.identity.federation.core.ErrorCodes;
import org.picketlink.identity.federation.core.saml.v2.constants.JBossSAMLURIConstants;
import org.picketlink.identity.federation.core.saml.v2.util.AssertionUtil;
import org.picketlink.identity.federation.core.util.StringUtil;
import org.picketlink.identity.federation.core.wstrust.SamlCredential;
import org.picketlink.identity.federation.core.wstrust.WSTrustException;
import org.picketlink.identity.federation.core.wstrust.plugins.saml.SAMLUtil;
import org.picketlink.identity.federation.saml.v2.assertion.AssertionType;
import org.picketlink.trust.jbossws.SAML2Constants;
import org.picketlink.trust.jbossws.Util;
import org.picketlink.trust.jbossws.handler.AbstractPicketLinkTrustHandler;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;
import org.jboss.ws.core.StubExt;

public class SAML2Handler extends AbstractPicketLinkTrustHandler
{ 
	public static final String ROLE_KEY_SYS_PROP = "picketlink.rolekey";
    private static PrintStream out = System.out;

   /**
    * Retrieves the SAML assertion from the SOAP payload and lets invocation go to JAAS for validation.
    */
    protected boolean handleInbound(MessageContext msgContext)
    { 
    	System.out.println("handleinbound method");
 	  // Handle Inbound Message
 	  // Flow should be validate assertion and load context with username-password
 	  String assertionNS = JBossSAMLURIConstants.ASSERTION_NSURI.get();
       SOAPMessageContext ctx = (SOAPMessageContext) msgContext;
       SOAPMessage soapMessage = ctx.getMessage();
       logToSystemOut(ctx, false) ;
       if(soapMessage == null)
          throw new IllegalStateException(ErrorCodes.NULL_VALUE + "SOAP Message");
       // retrieve the assertion
       Document document = soapMessage.getSOAPPart();
       Element soapHeader = Util.findOrCreateSoapHeader(document.getDocumentElement());
       Element assertion = Util.findElement(soapHeader, new QName(assertionNS, "Assertion"));
       if (assertion != null)
       {
          AssertionType assertionType = null;
          try
          {
             assertionType = SAMLUtil.fromElement(assertion);
             if(AssertionUtil.hasExpired(assertionType))
                throw new RuntimeException(ErrorCodes.EXPIRED_ASSERTION + "Assertion has expired");
          }
          catch(Exception e )
          { 
             log.error("Exception in parsing the assertion:",e);
          }
          SamlCredential credential = new SamlCredential(assertion);
          if (log.isTraceEnabled())
          {
             log.trace("Assertion included in SOAP payload:");
             log.trace(credential.getAssertionAsString());
          }
          Element subject = Util.findElement(assertion, new QName(assertionNS, "Subject"));
          Element nameID = Util.findElement(subject, new QName(assertionNS, "NameID"));
          String username = getUsername(nameID);
          System.out.println("username-->"+username);
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

             if(trace)
                log.trace("Inbound::Rolekeys to extract roles from the assertion:" + roleKeys);
             List<String> roles = AssertionUtil.getRoles(assertionType, roleKeys); 
             if(roles.size() > 0 )
             {
                if(trace)
                   log.trace("Inbound::Roles in the assertion:" + roles);
                Group roleGroup = SecurityActions.group(roles);
                theSubject.getPrincipals().add(roleGroup); 
             }
             else
             {
                if(trace)
                   log.trace("Inbound::Did not find roles in the assertion");
             } 
          } 
       }
       else
       {
          log.warn("Inbound::We did not find any assertion");
       } 
       return true;
    }
   

   protected boolean handleOutbound(MessageContext msgContext)
   { 
      if(trace)
      {
         log.trace("Handling Outbound Message");
      }
      SOAPMessageContext ctx = (SOAPMessageContext) msgContext;
      SOAPMessage soapMessage = ctx.getMessage();
      logToSystemOut(ctx, true); 
      // retrieve assertion first from the message context
      Element assertion = (Element) ctx.get(SAML2Constants.SAML2_ASSERTION_PROPERTY);
      
      //Assertion can also be obtained from the JAAS subject
      if( assertion == null)
      {
         assertion = getAssertionFromSubject();
      }
      
      if(assertion == null )
      {
         if(trace)
         {
            log.trace("Outbound::No Assertion was found on the message context or authenticated subject. Returning");
         }
         return true;
      }
      
      // add wsse header
      Document document = soapMessage.getSOAPPart();
      Element soapHeader = Util.findOrCreateSoapHeader(document.getDocumentElement());
      try
      {
         Element wsse = getSecurityHeaderElement(document);
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
      }
      catch (Exception e)
      {
         log.error(e);
         return false;
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
   /*
    * Check the MESSAGE_OUTBOUND_PROPERTY in the context
    * to see if this is an outgoing or incoming message.
    * Write a brief message to the print stream and
    * output the message. The writeTo() method can throw
    * SOAPException or IOException
    */
   private void logToSystemOut(SOAPMessageContext smc, boolean outbound) {
       if (outbound) {
           out.println("\nSAML2Handler log :: Outbound message");
       } else {
           out.println("\nSAML2Handler log :: Inbound message");
       }
       SOAPMessage message = smc.getMessage();
       try {
    	   System.out.println("\nSOAP XML Message-->");
           message.writeTo(out);
           System.out.println("\n<----SOAP XML Message");
       } catch (Exception e) {
           out.println("Exception in handler: " + e);
       }
       if(!outbound){
       try{
    	   System.out.println("SAML2Handler log :: Inbound Headers:");
           SOAPEnvelope soapEnv = message.getSOAPPart().getEnvelope();
           SOAPHeader soapHeader = soapEnv.getHeader();
           Iterator<?> i = soapHeader.getChildElements();
           while (i.hasNext()) {
        	    SOAPElement el = (SOAPElement) i.next(); 
        	    String tagName = el.getTagName(); 
        	    String value = el.getValue(); 
        	    out.println(tagName +" :: "+value);
        	}

           } catch(SOAPException e) {
               System.err.println(e);
           }

       }
   }

}