package mertz.security.oauth2.provider.token.store.cassandra;

import static org.junit.Assert.*;

import java.util.Collection;
import java.util.Date;
import java.util.UUID;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.ConfigFileApplicationContextInitializer;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.cassandra.core.CassandraOperations;
import org.springframework.data.cassandra.mapping.CassandraMappingContext;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.oauth2.common.DefaultExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.DefaultOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.RequestTokenFactory;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.TokenStoreBaseTests;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
@ContextConfiguration(initializers = ConfigFileApplicationContextInitializer.class)
@ActiveProfiles(profiles = "externalcassandra")
public class CassandraTokenStoreTests extends TokenStoreBaseTests {

  @Autowired
  private CassandraOperations cassandraOperations;

  @Autowired
  private CassandraMappingContext cassandraMappingContext;

  @Autowired
  private TokenStore cassandraTokenStore;

  @Override
  public TokenStore getTokenStore() {
    return cassandraTokenStore;
  }

  @Before
  public void setUp() throws Exception {
    cassandraMappingContext.getTableEntities().forEach(entity -> cassandraOperations.truncate(entity.getTableName()));
  }

  @Configuration
  @ComponentScan(basePackages = "mertz.security.oauth2.provider.token.store.cassandra")
  public static class SpringConfig {

  }

  @Test
  public void testExpiringRefreshToken() throws InterruptedException {
    String refreshToken = "refreshToken-" + UUID.randomUUID();
    DefaultOAuth2RefreshToken expectedExpiringRefreshToken = new DefaultExpiringOAuth2RefreshToken(refreshToken, new Date(System.currentTimeMillis() + 1000));
    OAuth2Authentication expectedAuthentication = new OAuth2Authentication(RequestTokenFactory.createOAuth2Request("id", false), new TestAuthentication("test2", false));
    getTokenStore().storeRefreshToken(expectedExpiringRefreshToken, expectedAuthentication);
    OAuth2RefreshToken actualExpiringRefreshToken = getTokenStore().readRefreshToken(refreshToken);
    assertEquals(expectedExpiringRefreshToken, actualExpiringRefreshToken);
    assertEquals(expectedAuthentication, getTokenStore().readAuthenticationForRefreshToken(expectedExpiringRefreshToken));
    // let the token expire
    Thread.sleep(2000);
    // now it should be gone
    assertNull(getTokenStore().readRefreshToken(refreshToken));
    assertNull(getTokenStore().readAuthenticationForRefreshToken(expectedExpiringRefreshToken));
  }

  @Test
  public void testExpiringAccessToken() throws InterruptedException {
    String accessToken = "accessToken-" + UUID.randomUUID();
    OAuth2Authentication expectedAuthentication = new OAuth2Authentication(RequestTokenFactory.createOAuth2Request("id", false), new TestAuthentication("test2", false));
    DefaultOAuth2AccessToken expectedOAuth2AccessToken = new DefaultOAuth2AccessToken(accessToken);
    expectedOAuth2AccessToken.setExpiration(new Date(System.currentTimeMillis() + 1000));
    getTokenStore().storeAccessToken(expectedOAuth2AccessToken, expectedAuthentication);
    OAuth2AccessToken actualOAuth2AccessToken = getTokenStore().readAccessToken(accessToken);
    assertEquals(expectedOAuth2AccessToken, actualOAuth2AccessToken);
    assertEquals(expectedAuthentication, getTokenStore().readAuthentication(expectedOAuth2AccessToken));
    // let the token expire
    Thread.sleep(2000);
    // now it should be gone
    assertNull(getTokenStore().readAccessToken(accessToken));
    assertNull(getTokenStore().readAuthentication(expectedOAuth2AccessToken));
  }

  @Test
  public void storeAccessTokenWithoutRefreshTokenRemoveAccessTokenVerifyTokenRemoved() {
    OAuth2Request request = RequestTokenFactory.createOAuth2Request("clientId", false);
    TestingAuthenticationToken authentication = new TestingAuthenticationToken("user", "password");
    String accessToken = "accessToken-" + UUID.randomUUID();
    OAuth2AccessToken oauth2AccessToken = new DefaultOAuth2AccessToken(accessToken);
    OAuth2Authentication oauth2Authentication = new OAuth2Authentication(request, authentication);
    getTokenStore().storeAccessToken(oauth2AccessToken, oauth2Authentication);
    getTokenStore().removeAccessToken(oauth2AccessToken);
    Collection<OAuth2AccessToken> oauth2AccessTokens = getTokenStore().findTokensByClientId(request.getClientId());
    assertTrue(oauth2AccessTokens.isEmpty());
  }

  @Test
  public void storeExpiringAccessTokenWithRefreshToken_RemoveExpiredAccessTokenUsingRefreshToken() throws InterruptedException {
    String accessToken = "accessToken-" + UUID.randomUUID();
    OAuth2Authentication expectedAuthentication = new OAuth2Authentication(RequestTokenFactory.createOAuth2Request("id", false), new TestAuthentication("test2", false));
    DefaultOAuth2AccessToken expectedOAuth2AccessToken = new DefaultOAuth2AccessToken(accessToken);
    expectedOAuth2AccessToken.setExpiration(new Date(System.currentTimeMillis() + 1000));
    String refreshToken = "refreshToken-" + UUID.randomUUID();
    DefaultOAuth2RefreshToken expectedRefreshToken = new DefaultOAuth2RefreshToken(refreshToken);
    expectedOAuth2AccessToken.setRefreshToken(expectedRefreshToken);
    getTokenStore().storeAccessToken(expectedOAuth2AccessToken, expectedAuthentication);
    // let the access token expire
    Thread.sleep(2000);
    // now it should be gone
    assertNull(getTokenStore().readAccessToken(accessToken));
    // use refresh token to remove already expired access token, expect no issues since access token has already been removed.
    getTokenStore().removeAccessTokenUsingRefreshToken(expectedRefreshToken);
  }

  @Test
  public void storeAccessTokenWithRefreshToken_RemoveAccessTokenUsingRefreshToken() throws InterruptedException {
    String accessToken = "accessToken-" + UUID.randomUUID();
    OAuth2Authentication expectedAuthentication = new OAuth2Authentication(RequestTokenFactory.createOAuth2Request("id", false), new TestAuthentication("test2", false));
    DefaultOAuth2AccessToken expectedOAuth2AccessToken = new DefaultOAuth2AccessToken(accessToken);
    String refreshToken = "refreshToken-" + UUID.randomUUID();
    DefaultOAuth2RefreshToken expectedRefreshToken = new DefaultOAuth2RefreshToken(refreshToken);
    expectedOAuth2AccessToken.setRefreshToken(expectedRefreshToken);
    getTokenStore().storeAccessToken(expectedOAuth2AccessToken, expectedAuthentication);
    // make sure access token is in the repository
    OAuth2AccessToken actualOAuth2AccessToken = getTokenStore().readAccessToken(accessToken);
    assertEquals(expectedOAuth2AccessToken, actualOAuth2AccessToken);
    // use refresh token to remove access token
    getTokenStore().removeAccessTokenUsingRefreshToken(expectedRefreshToken);
    // now it should be gone
    assertNull(getTokenStore().readAccessToken(accessToken));
  }

}
