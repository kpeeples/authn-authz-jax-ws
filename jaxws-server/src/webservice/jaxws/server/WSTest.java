package webservice.jaxws.server;
 
import javax.ejb.Remote;
import javax.jws.WebService;
 
@Remote
@WebService
public interface WSTest {
 
    public void echo(String echo);
}
