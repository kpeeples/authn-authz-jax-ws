package webservice.jaxws.server;
 
import javax.annotation.Resource;
import javax.ejb.Stateless;
import javax.jws.WebMethod;
import javax.jws.WebService;
import javax.xml.ws.WebServiceContext;
 
import org.jboss.ejb3.annotation.SecurityDomain;
import org.jboss.ws.annotation.EndpointConfig;
import org.jboss.wsf.spi.annotation.WebContext;
 
@Stateless(name = "SecureEndpoint")
@WebContext(contextRoot = "/sampleDomain")
@WebService  //webservice annotation
@EndpointConfig(configName = "SAML WSSecurity Endpoint") //this is required
@SecurityDomain("sts-wstest")
public class WSTestBean implements WSTest {
    
    @Resource
    WebServiceContext wsCtx;
 
    @WebMethod
    public void echo(String echo) {
        System.out.println("WSTest: " + echo);
        System.out.println("Principal: " + wsCtx.getUserPrincipal());
        System.out.println("Principal.getName(): " + wsCtx.getUserPrincipal().getName());
        System.out.println("isUserInRole('testRole'): " + wsCtx.isUserInRole("testRole"));
    }
}
