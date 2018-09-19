package mertz.security.oauth2.provider.token.store.cassandra.cfg;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.AuthenticationKeyGenerator;
import org.springframework.security.oauth2.provider.token.DefaultAuthenticationKeyGenerator;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import com.fasterxml.jackson.databind.ObjectWriter;

@Configuration
public class OAuthUtil {

  private static final Logger logger = LoggerFactory.getLogger(OAuthUtil.class);

  private static ObjectReader OAUTH2ACCESSTOKEN_OBJECT_READER = new ObjectMapper().readerFor(OAuth2AccessToken.class);

  private static ObjectWriter OAUTH2ACCESSTOKEN_OBJECT_WRITER = new ObjectMapper().writerFor(OAuth2AccessToken.class);

  @Bean
  public AuthenticationKeyGenerator getAuthenticationKeyGenerator() {
    return new DefaultAuthenticationKeyGenerator();
  }

  public static OAuth2AccessToken deserializeOAuth2AccessToken(String jsonOAuth2AccessToken) {
    try {
      return OAUTH2ACCESSTOKEN_OBJECT_READER.readValue(jsonOAuth2AccessToken);
    } catch (Exception e) {
      logger.error("Error converting json string to OAuth2AccessToken. {}", jsonOAuth2AccessToken);
      throw new RuntimeException(e);
    }
  }

  public static String serializeOAuth2AccessToken(OAuth2AccessToken oAuth2AccessToken) {
    try {
      return OAUTH2ACCESSTOKEN_OBJECT_WRITER.writeValueAsString(oAuth2AccessToken);
    } catch (Exception e) {
      logger.error("Error converting OAuth2AccessToken to json string. {}", oAuth2AccessToken);
      throw new RuntimeException(e);
    }
  }

  public static String getApprovalKey(OAuth2Authentication authentication) {
    String userName = authentication.getUserAuthentication() == null ? "" : authentication.getUserAuthentication().getName();
    return getApprovalKey(authentication.getOAuth2Request().getClientId(), userName);
  }

  public static String getApprovalKey(String clientId, String userName) {
    return clientId + (userName == null ? "" : ":" + userName);
  }

}
