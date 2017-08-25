package mertz.security.oauth2.provider.token.store.cassandra.cfg;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.provider.token.AuthenticationKeyGenerator;
import org.springframework.security.oauth2.provider.token.DefaultAuthenticationKeyGenerator;

import com.fasterxml.jackson.databind.ObjectMapper;

@Configuration
public class OAuthUtil {

  @Bean
  public AuthenticationKeyGenerator getAuthenticationKeyGenerator() {
    return new DefaultAuthenticationKeyGenerator();
  }

  @Bean
  public ObjectMapper getObjectMapper() {
    return new ObjectMapper();
  }

}
