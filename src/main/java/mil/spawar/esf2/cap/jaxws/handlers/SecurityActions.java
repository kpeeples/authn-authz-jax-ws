package mil.spawar.esf2.cap.jaxws.handlers;

import java.security.AccessController;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.security.acl.Group;
import java.util.List;

import javax.security.auth.Subject;

import org.jboss.security.SecurityConstants;
import org.jboss.security.SecurityContext;
import org.jboss.security.SecurityContextAssociation;
import org.jboss.security.SecurityContextFactory;
import org.jboss.security.SimplePrincipal;
import org.picketlink.identity.federation.bindings.jboss.subject.PicketLinkGroup;

/**
 * Privileged actions.
 * 
 * @author <a href="mmoyses@redhat.com">Marcus Moyses</a>
 * @author Anil Saldhana
 * @version $Revision: 1 $
 */
class SecurityActions
{ 
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
}