package mertz.security.oauth2.provider.token.store.cassandra;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.cassandra.core.CassandraBatchOperations;
import org.springframework.data.cassandra.core.CassandraTemplate;
import org.springframework.data.cassandra.core.cql.WriteOptions;
import org.springframework.data.cassandra.core.mapping.CassandraMappingContext;
import org.springframework.security.oauth2.common.ExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.common.util.SerializationUtils;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.AuthenticationKeyGenerator;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.stereotype.Component;

import com.datastax.driver.core.RegularStatement;

import mertz.security.oauth2.provider.token.store.cassandra.cfg.OAuthUtil;
import mertz.security.oauth2.provider.token.store.cassandra.model.AccessToken;
import mertz.security.oauth2.provider.token.store.cassandra.model.Authentication;
import mertz.security.oauth2.provider.token.store.cassandra.model.AuthenticationToAccessToken;
import mertz.security.oauth2.provider.token.store.cassandra.model.ClientIdToAccessToken;
import mertz.security.oauth2.provider.token.store.cassandra.model.RefreshToken;
import mertz.security.oauth2.provider.token.store.cassandra.model.RefreshTokenAuthentication;
import mertz.security.oauth2.provider.token.store.cassandra.model.RefreshTokenToAccessToken;
import mertz.security.oauth2.provider.token.store.cassandra.model.UsernameToAccessToken;
import mertz.security.oauth2.provider.token.store.cassandra.repo.AccessTokenRepository;
import mertz.security.oauth2.provider.token.store.cassandra.repo.AuthenticationRepository;
import mertz.security.oauth2.provider.token.store.cassandra.repo.AuthenticationToAccessTokenRepository;
import mertz.security.oauth2.provider.token.store.cassandra.repo.ClientIdToAccessTokenRepository;
import mertz.security.oauth2.provider.token.store.cassandra.repo.RefreshTokenAuthenticationRepository;
import mertz.security.oauth2.provider.token.store.cassandra.repo.RefreshTokenRepository;
import mertz.security.oauth2.provider.token.store.cassandra.repo.RefreshTokenToAccessTokenRepository;
import mertz.security.oauth2.provider.token.store.cassandra.repo.UsernameToAccessTokenRepository;

@Component
public class CassandraTokenStore implements TokenStore {

  private static final Logger logger = LoggerFactory.getLogger(CassandraTokenStore.class);

  private final AuthenticationRepository authenticationRepository;

  private final AccessTokenRepository accessTokenRepository;

  private final RefreshTokenRepository refreshTokenRepository;

  private final RefreshTokenAuthenticationRepository refreshTokenAuthenticationRepository;

  private final AuthenticationToAccessTokenRepository authenticationToAccessTokenRepository;

  private final UsernameToAccessTokenRepository usernameToAccessTokenRepository;

  private final ClientIdToAccessTokenRepository clientIdToAccessTokenRepository;

  private final RefreshTokenToAccessTokenRepository refreshTokenToAccessTokenRepository;

  private final CassandraTemplate cassandraTemplate;

  private final AuthenticationKeyGenerator authenticationKeyGenerator;

  @Autowired
  public CassandraTokenStore(AuthenticationRepository authenticationRepository,
                             AccessTokenRepository accessTokenRepository,
                             RefreshTokenRepository refreshTokenRepository,
                             RefreshTokenAuthenticationRepository refreshTokenAuthenticationRepository,
                             AuthenticationToAccessTokenRepository authenticationToAccessTokenRepository,
                             UsernameToAccessTokenRepository usernameToAccessTokenRepository,
                             ClientIdToAccessTokenRepository clientIdToAccessTokenRepository,
                             RefreshTokenToAccessTokenRepository refreshTokenToAccessTokenRepository,
                             CassandraTemplate cassandraTemplate,
                             AuthenticationKeyGenerator authenticationKeyGenerator) {
    this.authenticationRepository = authenticationRepository;
    this.accessTokenRepository = accessTokenRepository;
    this.refreshTokenRepository = refreshTokenRepository;
    this.refreshTokenAuthenticationRepository = refreshTokenAuthenticationRepository;
    this.authenticationToAccessTokenRepository = authenticationToAccessTokenRepository;
    this.usernameToAccessTokenRepository = usernameToAccessTokenRepository;
    this.clientIdToAccessTokenRepository = clientIdToAccessTokenRepository;
    this.refreshTokenToAccessTokenRepository = refreshTokenToAccessTokenRepository;
    this.cassandraTemplate = cassandraTemplate;
    this.authenticationKeyGenerator = authenticationKeyGenerator;
  }

  @Override
  public OAuth2Authentication readAuthentication(OAuth2AccessToken token) {
    return readAuthentication(token.getValue());
  }

  @Override
  public OAuth2Authentication readAuthentication(String token) {
    return authenticationRepository
        .findById(token)
        .map(authentication ->
          deserializeOAuth2Authentication(authentication.getoAuth2Authentication()))
        .orElse(null);
  }

  @Override
  public void storeAccessToken(OAuth2AccessToken token, OAuth2Authentication authentication) {
    String jsonAccessToken = OAuthUtil.serializeOAuth2AccessToken(token);
    byte[] serializedOAuth2Authentication = SerializationUtils.serialize(authentication);
    ByteBuffer bufferedOAuth2Authentication = ByteBuffer.wrap(serializedOAuth2Authentication);
    WriteOptions.WriteOptionsBuilder accessWriteOptionsBuilder = WriteOptions.builder();
    if (token.getExpiration() != null) {
      int seconds = token.getExpiresIn();
      accessWriteOptionsBuilder.ttl(seconds);
    }
    WriteOptions accessWriteOptions = accessWriteOptionsBuilder.build();

    CassandraBatchOperations batch = cassandraTemplate.batchOps()
        .insert(Collections.singleton(new AccessToken(token.getValue(), jsonAccessToken)), accessWriteOptions)
        .insert(Collections.singleton(new Authentication(token.getValue(), bufferedOAuth2Authentication)),
            accessWriteOptions)
        .insert(Collections.singleton(
            new AuthenticationToAccessToken(authenticationKeyGenerator.extractKey(authentication), jsonAccessToken)),
            accessWriteOptions)
        .insert(Collections.singleton(
            new UsernameToAccessToken(OAuthUtil.getApprovalKey(authentication), jsonAccessToken)),
            accessWriteOptions)
        .insert(Collections.singleton(
            new ClientIdToAccessToken(authentication.getOAuth2Request().getClientId(), jsonAccessToken)),
            accessWriteOptions);

    OAuth2RefreshToken oAuth2RefreshToken = token.getRefreshToken();
    if (oAuth2RefreshToken != null && oAuth2RefreshToken.getValue() != null) {
      WriteOptions refreshWriteOptions = buildRefreshTokenWriteOptions(oAuth2RefreshToken);

      batch = batch.insert(
          Collections.singleton(new RefreshTokenToAccessToken(token.getRefreshToken().getValue(), token.getValue())),
          refreshWriteOptions);
    }
    batch.execute();
  }

  @Override
  public OAuth2AccessToken readAccessToken(String tokenValue) {
    return accessTokenRepository.findById(tokenValue).map( accessToken ->
      OAuthUtil.deserializeOAuth2AccessToken(accessToken.getoAuth2AccessToken())
    ).orElse(null);
  }

  @Override
  public void removeAccessToken(OAuth2AccessToken token) {
    prepareRemoveAccessTokenStatements(token).execute();
  }

  private CassandraBatchOperations prepareRemoveAccessTokenStatements(OAuth2AccessToken token) {
    CassandraBatchOperations batch = cassandraTemplate.batchOps();
    String tokenValue = token.getValue();
    String jsonOAuth2AccessToken = OAuthUtil.serializeOAuth2AccessToken(token);

    batch.delete(new AccessToken(tokenValue,null));
    // Lookup Authentication table for further deleting from AuthenticationToAccessToken table
    authenticationRepository.findById(tokenValue).ifPresent(authentication -> {
      ByteBuffer bufferedOAuth2Authentication = authentication.getoAuth2Authentication();
      byte[] serializedOAuth2Authentication = new byte[bufferedOAuth2Authentication.remaining()];
      bufferedOAuth2Authentication.get(serializedOAuth2Authentication);
      OAuth2Authentication oAuth2Authentication = SerializationUtils.deserialize(serializedOAuth2Authentication);
      String clientId = oAuth2Authentication.getOAuth2Request().getClientId();

      batch.delete(authentication);
      batch.delete(new AuthenticationToAccessToken(
          authenticationKeyGenerator.extractKey(oAuth2Authentication),null));

      // Delete from UsernameToAccessToken table
      usernameToAccessTokenRepository
          .findByKeyAndOAuth2AccessToken(
              OAuthUtil.getApprovalKey(clientId, oAuth2Authentication.getName()),
              jsonOAuth2AccessToken)
          .ifPresent(batch::delete);

      // Delete from ClientIdToAccessToken table
      clientIdToAccessTokenRepository
          .findByKeyAndOAuth2AccessToken(clientId, jsonOAuth2AccessToken)
          .ifPresent(batch::delete);
    });

    return batch;
  }

  @Override
  public void storeRefreshToken(OAuth2RefreshToken refreshToken, OAuth2Authentication authentication) {
    List<RegularStatement> statementList = new ArrayList<RegularStatement>();

    byte[] serializedRefreshToken = SerializationUtils.serialize(refreshToken);
    ByteBuffer bufferedRefreshToken = ByteBuffer.wrap(serializedRefreshToken);

    byte[] serializedAuthentication = SerializationUtils.serialize(authentication);
    ByteBuffer bufferedAuthentication = ByteBuffer.wrap(serializedAuthentication);

    WriteOptions refreshWriteOptions = buildRefreshTokenWriteOptions(refreshToken);

    cassandraTemplate.batchOps()
        .insert(Collections.singleton(new RefreshToken(refreshToken.getValue(), bufferedRefreshToken)),
            refreshWriteOptions)
        .insert(Collections.singleton(new RefreshTokenAuthentication(refreshToken.getValue(), bufferedAuthentication)),
            refreshWriteOptions)
        .execute();
  }

  private WriteOptions buildRefreshTokenWriteOptions(OAuth2RefreshToken refreshToken) {
    WriteOptions.WriteOptionsBuilder refreshWriteOptionsBuilder = WriteOptions.builder();
    if (refreshToken instanceof ExpiringOAuth2RefreshToken) {
      ExpiringOAuth2RefreshToken expiringRefreshToken = (ExpiringOAuth2RefreshToken) refreshToken;
      Date expiration = expiringRefreshToken.getExpiration();
      if (expiration != null) {
        int seconds = Long.valueOf((expiration.getTime() - System.currentTimeMillis()) / 1000L).intValue();
        refreshWriteOptionsBuilder.ttl(seconds);
      }
    }
    return refreshWriteOptionsBuilder.build();
  }

  @Override
  public OAuth2RefreshToken readRefreshToken(String tokenValue) {
    return refreshTokenRepository.findById(tokenValue).map(refreshToken -> {
      ByteBuffer bufferedRefreshToken = refreshToken.getoAuth2RefreshToken();
      byte[] serializedRefreshToken = new byte[bufferedRefreshToken.remaining()];
      bufferedRefreshToken.get(serializedRefreshToken);
      return SerializationUtils.<OAuth2RefreshToken>deserialize(serializedRefreshToken);
    }).orElse(null);
  }

  @Override
  public OAuth2Authentication readAuthenticationForRefreshToken(OAuth2RefreshToken token) {
    return refreshTokenAuthenticationRepository.findById(token.getValue()).map(refreshTokenAuthentication ->
        deserializeOAuth2Authentication(refreshTokenAuthentication.getoAuth2Authentication()))
        .orElse(null);
  }

  private OAuth2Authentication deserializeOAuth2Authentication(ByteBuffer byteBuffer) {
    byte[] serializedOAuth2Authentication = new byte[byteBuffer.remaining()];
    byteBuffer.get(serializedOAuth2Authentication);
    return SerializationUtils.deserialize(serializedOAuth2Authentication);
  }

  @Override
  public void removeRefreshToken(OAuth2RefreshToken token) {
    String tokenValue = token.getValue();
    cassandraTemplate.batchOps()
        .delete(new RefreshToken(tokenValue,null))
        .delete(new RefreshTokenAuthentication(tokenValue,null))
        .delete(new RefreshTokenToAccessToken(tokenValue, null))
        .execute();
  }

  @Override
  public void removeAccessTokenUsingRefreshToken(OAuth2RefreshToken refreshToken) {
    String tokenValue = refreshToken.getValue();
    // Lookup RefreshTokenToAccessToken table for locating access token
    refreshTokenToAccessTokenRepository.findById(tokenValue).ifPresent(refreshTokenToAccessToken -> {
      String accessTokenKey = refreshTokenToAccessToken.getAccessTokenKey();
      accessTokenRepository.findById(accessTokenKey).ifPresent(accessToken -> {

        String jsonOAuth2AccessToken = accessToken.getoAuth2AccessToken();
        OAuth2AccessToken oAuth2AccessToken = OAuthUtil.deserializeOAuth2AccessToken(jsonOAuth2AccessToken);
        // Delete access token from all related tables
        CassandraBatchOperations batch = prepareRemoveAccessTokenStatements(oAuth2AccessToken);
        // Delete from RefreshTokenToAccessToken table
        batch = batch.delete(refreshTokenToAccessToken);
        batch.execute();
      });
    });
  }

  @Override
  public OAuth2AccessToken getAccessToken(OAuth2Authentication authentication) {
    String key = authenticationKeyGenerator.extractKey(authentication);
    return authenticationToAccessTokenRepository.findById(key).map(authenticationToAccessToken -> {
      OAuth2AccessToken oAuth2AccessToken = OAuthUtil.deserializeOAuth2AccessToken(authenticationToAccessToken.getoAuth2AccessToken());
      if (oAuth2AccessToken != null && !key.equals(authenticationKeyGenerator.extractKey(readAuthentication(oAuth2AccessToken.getValue())))) {
        storeAccessToken(oAuth2AccessToken, authentication);
      }
      return oAuth2AccessToken;
    }).orElse(null);
  }

  @Override
  public Collection<OAuth2AccessToken> findTokensByClientIdAndUserName(String clientId, String userName) {
    return usernameToAccessTokenRepository.findByKey(OAuthUtil.getApprovalKey(clientId, userName))
      .map(usernameToAccessTokens ->
        usernameToAccessTokens.stream()
          .map(usernameToAccessToken ->
            OAuthUtil.deserializeOAuth2AccessToken(usernameToAccessToken.getOAuth2AccessToken()))
          .collect(Collectors.toSet()))
      .orElse(Collections.emptySet());
  }

  @Override
  public Collection<OAuth2AccessToken> findTokensByClientId(String clientId) {
    return clientIdToAccessTokenRepository.findByKey(clientId)
      .map(clientIdToAccessTokens ->
        clientIdToAccessTokens.stream()
          .map(clientIdToAccessToken ->
            OAuthUtil.deserializeOAuth2AccessToken(clientIdToAccessToken.getOAuth2AccessToken()))
          .collect(Collectors.toSet()))
      .orElse(Collections.emptySet());
  }

}
