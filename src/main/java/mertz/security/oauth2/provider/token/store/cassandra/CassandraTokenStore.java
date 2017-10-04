package mertz.security.oauth2.provider.token.store.cassandra;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cassandra.core.WriteOptions;
import org.springframework.data.cassandra.core.CassandraTemplate;
import org.springframework.data.cassandra.mapping.CassandraMappingContext;
import org.springframework.security.oauth2.common.ExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.common.util.SerializationUtils;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.AuthenticationKeyGenerator;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.stereotype.Component;

import com.datastax.driver.core.RegularStatement;
import com.datastax.driver.core.querybuilder.Batch;
import com.datastax.driver.core.querybuilder.Delete;
import com.datastax.driver.core.querybuilder.Insert;
import com.datastax.driver.core.querybuilder.QueryBuilder;

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

  @Autowired
  private AuthenticationRepository authenticationRepository;

  @Autowired
  private AccessTokenRepository accessTokenRepository;

  @Autowired
  private RefreshTokenRepository refreshTokenRepository;

  @Autowired
  private RefreshTokenAuthenticationRepository refreshTokenAuthenticationRepository;

  @Autowired
  private AuthenticationToAccessTokenRepository authenticationToAccessTokenRepository;

  @Autowired
  private UsernameToAccessTokenRepository usernameToAccessTokenRepository;

  @Autowired
  private ClientIdToAccessTokenRepository clientIdToAccessTokenRepository;

  @Autowired
  private RefreshTokenToAccessTokenRepository refreshTokenToAccessTokenRepository;

  @Autowired
  private CassandraTemplate cassandraTemplate;

  @Autowired
  private CassandraMappingContext cassandraMappingContext;

  @Autowired
  private AuthenticationKeyGenerator authenticationKeyGenerator;

  @Override
  public OAuth2Authentication readAuthentication(OAuth2AccessToken token) {
    return readAuthentication(token.getValue());
  }

  @Override
  public OAuth2Authentication readAuthentication(String token) {
    Authentication authentication = authenticationRepository.findOne(token);
    if (authentication != null) {
      ByteBuffer bufferedOAuth2Authentication = authentication.getoAuth2Authentication();
      byte[] serializedOAuth2Authentication = new byte[bufferedOAuth2Authentication.remaining()];
      bufferedOAuth2Authentication.get(serializedOAuth2Authentication);
      OAuth2Authentication oAuth2Authentication = SerializationUtils.deserialize(serializedOAuth2Authentication);
      return oAuth2Authentication;
    } else {
      return null;
    }
  }

  @Override
  public void storeAccessToken(OAuth2AccessToken token, OAuth2Authentication authentication) {
    List<RegularStatement> statementList = new ArrayList<RegularStatement>();
    String jsonAccessToken = OAuthUtil.serializeOAuth2AccessToken(token);
    byte[] serializedOAuth2Authentication = SerializationUtils.serialize(authentication);
    ByteBuffer bufferedOAuth2Authentication = ByteBuffer.wrap(serializedOAuth2Authentication);
    WriteOptions accessWriteOptions = new WriteOptions();
    if (token.getExpiration() != null) {
      int seconds = token.getExpiresIn();
      accessWriteOptions.setTtl(seconds);
    }

    // Insert into AccessToken table
    Insert accessInsert = CassandraTemplate.createInsertQuery(AccessToken.TABLE, new AccessToken(token.getValue(), jsonAccessToken), accessWriteOptions, cassandraTemplate.getConverter());
    statementList.add(accessInsert);

    // Insert into Authentication table
    Insert authInsert = CassandraTemplate.createInsertQuery(Authentication.TABLE, new Authentication(token.getValue(), bufferedOAuth2Authentication), accessWriteOptions, cassandraTemplate.getConverter());
    statementList.add(authInsert);

    // Insert into AuthenticationToAccessToken table
    Insert authToAccessInsert = CassandraTemplate.createInsertQuery(AuthenticationToAccessToken.TABLE, new AuthenticationToAccessToken(authenticationKeyGenerator.extractKey(authentication), jsonAccessToken), accessWriteOptions, cassandraTemplate.getConverter());
    statementList.add(authToAccessInsert);

    // Insert into UsernameToAccessToken table
    Insert unameToAccessInsert = CassandraTemplate.createInsertQuery(UsernameToAccessToken.TABLE, new UsernameToAccessToken(OAuthUtil.getApprovalKey(authentication), jsonAccessToken), accessWriteOptions, cassandraTemplate.getConverter());
    statementList.add(unameToAccessInsert);

    // Insert into ClientIdToAccessToken table
    Insert clientIdToAccessInsert = CassandraTemplate.createInsertQuery(ClientIdToAccessToken.TABLE, new ClientIdToAccessToken(authentication.getOAuth2Request().getClientId(), jsonAccessToken), accessWriteOptions, cassandraTemplate.getConverter());
    statementList.add(clientIdToAccessInsert);

    OAuth2RefreshToken oAuth2RefreshToken = token.getRefreshToken();
    if (oAuth2RefreshToken != null && oAuth2RefreshToken.getValue() != null) {
      WriteOptions refreshWriteOptions = new WriteOptions();
      if (oAuth2RefreshToken instanceof ExpiringOAuth2RefreshToken) {
        ExpiringOAuth2RefreshToken expiringRefreshToken = (ExpiringOAuth2RefreshToken) oAuth2RefreshToken;
        Date expiration = expiringRefreshToken.getExpiration();
        if (expiration != null) {
          int seconds = Long.valueOf((expiration.getTime() - System.currentTimeMillis()) / 1000L).intValue();
          refreshWriteOptions.setTtl(seconds);
        }
      }
      // Insert into RefreshTokenToAccessToken table
      Insert refreshTokenToAccessTokenInsert = CassandraTemplate.createInsertQuery(RefreshTokenToAccessToken.TABLE, new RefreshTokenToAccessToken(token.getRefreshToken().getValue(), token.getValue()), refreshWriteOptions, cassandraTemplate.getConverter());
      statementList.add(refreshTokenToAccessTokenInsert);
    }

    Batch batch = QueryBuilder.batch(statementList.toArray(new RegularStatement[statementList.size()]));
    cassandraTemplate.execute(batch);
  }

  @Override
  public OAuth2AccessToken readAccessToken(String tokenValue) {
    AccessToken accessToken = accessTokenRepository.findOne(tokenValue);
    if (accessToken != null) {
      return OAuthUtil.deserializeOAuth2AccessToken(accessToken.getoAuth2AccessToken());
    } else {
      return null;
    }
  }

  @Override
  public void removeAccessToken(OAuth2AccessToken token) {
    List<RegularStatement> statementList = prepareRemoveAccessTokenStatements(token);
    Batch batch = QueryBuilder.batch(statementList.toArray(new RegularStatement[statementList.size()]));
    cassandraTemplate.execute(batch);
  }

  private List<RegularStatement> prepareRemoveAccessTokenStatements(OAuth2AccessToken token) {
    //String tokenId = token.getValue();
    String tokenValue = token.getValue();
    String jsonOAuth2AccessToken = OAuthUtil.serializeOAuth2AccessToken(token);
    List<RegularStatement> statementList = new ArrayList<RegularStatement>();
    
    // Delete from AccessToken table
    RegularStatement accessTokenDelete = prepareDeleteByPrimaryKeyRegularStatement(AccessToken.class, tokenValue);
    statementList.add(accessTokenDelete);

    // Lookup Authentication table for further deleting from AuthenticationToAccessToken table
    Authentication authentication = authenticationRepository.findOne(tokenValue);
    if (authentication != null) {
      ByteBuffer bufferedOAuth2Authentication = authentication.getoAuth2Authentication();
      byte[] serializedOAuth2Authentication = new byte[bufferedOAuth2Authentication.remaining()];
      bufferedOAuth2Authentication.get(serializedOAuth2Authentication);
      OAuth2Authentication oAuth2Authentication = SerializationUtils.deserialize(serializedOAuth2Authentication);
      String clientId = oAuth2Authentication.getOAuth2Request().getClientId();

      // Delete from Authentication table
      RegularStatement authenticationDelete = prepareDeleteByPrimaryKeyRegularStatement(Authentication.class, tokenValue);
      statementList.add(authenticationDelete);

      // Delete from AuthenticationToAccessToken table
      RegularStatement authToAccessDelete = prepareDeleteByPrimaryKeyRegularStatement(AuthenticationToAccessToken.class, authenticationKeyGenerator.extractKey(oAuth2Authentication));
      statementList.add(authToAccessDelete);

      // Delete from UsernameToAccessToken table
      Optional<UsernameToAccessToken> optionalUsernameToAccessToken = usernameToAccessTokenRepository.findByKeyAndOAuth2AccessToken(OAuthUtil.getApprovalKey(clientId, oAuth2Authentication.getName()), jsonOAuth2AccessToken);
      optionalUsernameToAccessToken.ifPresent(usernameToAccessToken -> {
        Delete usernameToAccessDelete = CassandraTemplate.createDeleteQuery(UsernameToAccessToken.TABLE, usernameToAccessToken, null, cassandraTemplate.getConverter());
        statementList.add(usernameToAccessDelete);
      });

      // Delete from ClientIdToAccessToken table
      Optional<ClientIdToAccessToken> optionalClientIdToAccessToken = clientIdToAccessTokenRepository.findByKeyAndOAuth2AccessToken(clientId, jsonOAuth2AccessToken);
      optionalClientIdToAccessToken.ifPresent(clientIdToAccessToken -> {
        Delete clientIdToAccessDelete = CassandraTemplate.createDeleteQuery(ClientIdToAccessToken.TABLE, clientIdToAccessToken, null, cassandraTemplate.getConverter());
        statementList.add(clientIdToAccessDelete);
      });
    }

    return statementList;
  }

  @Override
  public void storeRefreshToken(OAuth2RefreshToken refreshToken, OAuth2Authentication authentication) {
    List<RegularStatement> statementList = new ArrayList<RegularStatement>();

    byte[] serializedRefreshToken = SerializationUtils.serialize(refreshToken);
    ByteBuffer bufferedRefreshToken = ByteBuffer.wrap(serializedRefreshToken);

    byte[] serializedAuthentication = SerializationUtils.serialize(authentication);
    ByteBuffer bufferedAuthentication = ByteBuffer.wrap(serializedAuthentication);

    WriteOptions refreshWriteOptions = new WriteOptions();
    if (refreshToken instanceof ExpiringOAuth2RefreshToken) {
      ExpiringOAuth2RefreshToken expiringRefreshToken = (ExpiringOAuth2RefreshToken) refreshToken;
      Date expiration = expiringRefreshToken.getExpiration();
      if (expiration != null) {
        int seconds = Long.valueOf((expiration.getTime() - System.currentTimeMillis()) / 1000L).intValue();
        refreshWriteOptions.setTtl(seconds);
      }
    }

    // Insert into RefreshToken table
    Insert accessInsert = CassandraTemplate.createInsertQuery(RefreshToken.TABLE, new RefreshToken(refreshToken.getValue(), bufferedRefreshToken), refreshWriteOptions, cassandraTemplate.getConverter());
    statementList.add(accessInsert);

    // Insert into RefreshTokenAuthentication table
    Insert authInsert = CassandraTemplate.createInsertQuery(RefreshTokenAuthentication.TABLE, new RefreshTokenAuthentication(refreshToken.getValue(), bufferedAuthentication), refreshWriteOptions, cassandraTemplate.getConverter());
    statementList.add(authInsert);

    Batch batch = QueryBuilder.batch(statementList.toArray(new RegularStatement[statementList.size()]));
    cassandraTemplate.execute(batch);
  }

  @Override
  public OAuth2RefreshToken readRefreshToken(String tokenValue) {
    RefreshToken refreshToken = refreshTokenRepository.findOne(tokenValue);
    if (refreshToken != null) {
      ByteBuffer bufferedRefreshToken = refreshToken.getoAuth2RefreshToken();
      byte[] serializedRefreshToken = new byte[bufferedRefreshToken.remaining()];
      bufferedRefreshToken.get(serializedRefreshToken);
      OAuth2RefreshToken oAuth2RefreshToken = SerializationUtils.deserialize(serializedRefreshToken);
      return oAuth2RefreshToken;
    } else {
      return null;
    }
  }

  @Override
  public OAuth2Authentication readAuthenticationForRefreshToken(OAuth2RefreshToken token) {
    RefreshTokenAuthentication refreshTokenAuthentication = refreshTokenAuthenticationRepository.findOne(token.getValue());
    if (refreshTokenAuthentication != null) {
      ByteBuffer bufferedOAuth2Authentication = refreshTokenAuthentication.getoAuth2Authentication();
      byte[] serializedOAuth2Authentication = new byte[bufferedOAuth2Authentication.remaining()];
      bufferedOAuth2Authentication.get(serializedOAuth2Authentication);
      OAuth2Authentication oAuth2Authentication = SerializationUtils.deserialize(serializedOAuth2Authentication);
      return oAuth2Authentication;
    } else {
      return null;
    }
  }

  @Override
  public void removeRefreshToken(OAuth2RefreshToken token) {
    String tokenValue = token.getValue();
    List<RegularStatement> statementList = new ArrayList<RegularStatement>();
    // Delete from RefreshToken table
    statementList.add(prepareDeleteByPrimaryKeyRegularStatement(RefreshToken.class, tokenValue));
    // Delete from RefreshTokenAuthentication table
    statementList.add(prepareDeleteByPrimaryKeyRegularStatement(RefreshTokenAuthentication.class, tokenValue));
    // Delete from RefreshTokenToAccessToken table
    statementList.add(prepareDeleteByPrimaryKeyRegularStatement(RefreshTokenToAccessToken.class, tokenValue));
    Batch batch = QueryBuilder.batch(statementList.toArray(new RegularStatement[statementList.size()]));
    cassandraTemplate.execute(batch);
  }

  private RegularStatement prepareDeleteByPrimaryKeyRegularStatement(Class<?> repositoryClass, String primaryKeyValue) {
    RegularStatement deleteRegularStatement;
    try {
      deleteRegularStatement = QueryBuilder.delete().from(repositoryClass.getDeclaredField("TABLE").get(null).toString()).where(QueryBuilder.eq(cassandraMappingContext.getPersistentEntity(repositoryClass).getIdProperty().getColumnName().toCql(), primaryKeyValue));
    } catch (IllegalArgumentException | IllegalAccessException | NoSuchFieldException | SecurityException e) {
      logger.error("Error preparing delete statement for repository {}.", repositoryClass.getSimpleName());
      throw new RuntimeException(e);
    }
    return deleteRegularStatement;
  }

  @Override
  public void removeAccessTokenUsingRefreshToken(OAuth2RefreshToken refreshToken) {
    String tokenValue = refreshToken.getValue();
    // Lookup RefreshTokenToAccessToken table for locating access token
    RefreshTokenToAccessToken refreshTokenToAccessToken = refreshTokenToAccessTokenRepository.findOne(tokenValue);
    if (refreshTokenToAccessToken != null) {
      String accessTokenKey = refreshTokenToAccessToken.getAccessTokenKey();
      AccessToken accessToken = accessTokenRepository.findOne(accessTokenKey);
      String jsonOAuth2AccessToken = accessToken.getoAuth2AccessToken();
      OAuth2AccessToken oAuth2AccessToken = OAuthUtil.deserializeOAuth2AccessToken(jsonOAuth2AccessToken);
      // Delete access token from all related tables
      List<RegularStatement> statementList = prepareRemoveAccessTokenStatements(oAuth2AccessToken);
      // Delete from RefreshTokenToAccessToken table
      Delete refreshTokenToAccessTokenDelete = CassandraTemplate.createDeleteQuery(RefreshTokenToAccessToken.TABLE, refreshTokenToAccessToken, null, cassandraTemplate.getConverter());
      statementList.add(refreshTokenToAccessTokenDelete);
      Batch batch = QueryBuilder.batch(statementList.toArray(new RegularStatement[statementList.size()]));
      cassandraTemplate.execute(batch);
    }
  }

  @Override
  public OAuth2AccessToken getAccessToken(OAuth2Authentication authentication) {
    String key = authenticationKeyGenerator.extractKey(authentication);
    AuthenticationToAccessToken authenticationToAccessToken = authenticationToAccessTokenRepository.findOne(key);
    if (authenticationToAccessToken != null) {
      OAuth2AccessToken oAuth2AccessToken = OAuthUtil.deserializeOAuth2AccessToken(authenticationToAccessToken.getoAuth2AccessToken());
      if (oAuth2AccessToken != null && !key.equals(authenticationKeyGenerator.extractKey(readAuthentication(oAuth2AccessToken.getValue())))) {
        storeAccessToken(oAuth2AccessToken, authentication);
      }
      return oAuth2AccessToken;
    } else {
      return null;
    }
  }

  @Override
  public Collection<OAuth2AccessToken> findTokensByClientIdAndUserName(String clientId, String userName) {
    String key = OAuthUtil.getApprovalKey(clientId, userName);
    Optional<List<UsernameToAccessToken>> optionalUsernameToAccessTokenSet = usernameToAccessTokenRepository.findByKey(key);
    Set<OAuth2AccessToken> oAuth2AccessTokenSet = new HashSet<OAuth2AccessToken>();
    optionalUsernameToAccessTokenSet.ifPresent(usernameToAccessTokenSet -> {
      usernameToAccessTokenSet.forEach(usernameToAccessToken -> oAuth2AccessTokenSet.add(OAuthUtil.deserializeOAuth2AccessToken(usernameToAccessToken.getOAuth2AccessToken())));
    });
    return oAuth2AccessTokenSet;
  }

  @Override
  public Collection<OAuth2AccessToken> findTokensByClientId(String clientId) {
    Optional<List<ClientIdToAccessToken>> optionalClientIdToAccessTokenSet = clientIdToAccessTokenRepository.findByKey(clientId);
    Set<OAuth2AccessToken> oAuth2AccessTokenSet = new HashSet<OAuth2AccessToken>();
    optionalClientIdToAccessTokenSet.ifPresent(clientIdToAccessTokenSet -> {
      clientIdToAccessTokenSet.forEach(clientIdToAccessToken -> oAuth2AccessTokenSet.add(OAuthUtil.deserializeOAuth2AccessToken(clientIdToAccessToken.getOAuth2AccessToken())));
    });
    return oAuth2AccessTokenSet;
  }

}
