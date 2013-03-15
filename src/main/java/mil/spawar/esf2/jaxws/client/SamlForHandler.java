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

public class SamlForHandler 
{

	public Element issue(String user, String password)
	{
		Element assertion = null;
		try {
			WSTrustClient client = new WSTrustClient("PicketLinkSTS", "PicketLinkSTSPort","http://esf2:8080/picketlink-sts/PicketLinkSTS",new SecurityInfo(user, password));
			System.out.println("SamlForHandler :: Invoking token service to get SAML assertion for "+user);
			assertion = client.issueToken(SAMLUtil.SAML2_TOKEN_TYPE);
			System.out.println("SamlForHandler :: SAML assertion for UserA successfully obtained!-->"+assertion);
			SamlCredential credential = new SamlCredential(assertion);
			System.out.println("SamlForHandler :: Assertion included in SOAP payload:");
			System.out.println(credential.getAssertionAsString());
		} catch (Exception wse) {
			System.out.println("SamlForHandler :: Unable to issue assertion: " + wse.getMessage());
			wse.printStackTrace();
		}
		return assertion;
	}
}
