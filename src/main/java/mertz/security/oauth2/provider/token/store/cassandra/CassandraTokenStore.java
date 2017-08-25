package mertz.security.oauth2.provider.token.store.cassandra;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

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
import com.datastax.driver.core.querybuilder.Update;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

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

  @Autowired
  private ObjectMapper mapper;

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

    String jsonAccessToken;
    try {
      jsonAccessToken = mapper.writeValueAsString(token);
    } catch (JsonProcessingException e) {
      logger.error("Error converting OAuth2AccessToken to json.");
      throw new RuntimeException(e);
    }
    byte[] serializedOAuth2Authentication = SerializationUtils.serialize(authentication);
    ByteBuffer bufferedOAuth2Authentication = ByteBuffer.wrap(serializedOAuth2Authentication);
    WriteOptions accessWriteOptions = new WriteOptions();
    if (token.getExpiration() != null) {
      int seconds = token.getExpiresIn();
      accessWriteOptions.setTtl(seconds);
    }

    Insert accessInsert = CassandraTemplate.createInsertQuery(AccessToken.TABLE,
        new AccessToken(token.getValue(), jsonAccessToken), accessWriteOptions, cassandraTemplate.getConverter());
    statementList.add(accessInsert);

    Insert authInsert = CassandraTemplate.createInsertQuery(Authentication.TABLE,
        new Authentication(token.getValue(), bufferedOAuth2Authentication), accessWriteOptions,
        cassandraTemplate.getConverter());
    statementList.add(authInsert);

    Insert authToAccessInsert = CassandraTemplate.createInsertQuery(AuthenticationToAccessToken.TABLE,
        new AuthenticationToAccessToken(authenticationKeyGenerator.extractKey(authentication), jsonAccessToken),
        accessWriteOptions, cassandraTemplate.getConverter());
    statementList.add(authToAccessInsert);

    if (!authentication.isClientOnly()) {
      UsernameToAccessToken usernameToAccessToken = usernameToAccessTokenRepository.findOne(getApprovalKey(authentication));
      if (usernameToAccessToken == null) {
        Insert unameToAccessInsert = CassandraTemplate.createInsertQuery(UsernameToAccessToken.TABLE,
            new UsernameToAccessToken(getApprovalKey(authentication),
                Stream.of(jsonAccessToken).collect(Collectors.toCollection(HashSet::new))),
            accessWriteOptions, cassandraTemplate.getConverter());
        statementList.add(unameToAccessInsert);
      } else {
        usernameToAccessToken.getoAuth2AccessTokenSet().add(jsonAccessToken);
        Update unameToAccessUpdate = CassandraTemplate.createUpdateQuery(UsernameToAccessToken.TABLE,
            usernameToAccessToken, accessWriteOptions, cassandraTemplate.getConverter());
        statementList.add(unameToAccessUpdate);
      }
    }

    ClientIdToAccessToken clientIdToAccessToken = clientIdToAccessTokenRepository.findOne(authentication.getOAuth2Request().getClientId());
    if (clientIdToAccessToken == null) {
      Insert clientIdToAccessInsert = CassandraTemplate.createInsertQuery(ClientIdToAccessToken.TABLE,
          new ClientIdToAccessToken(authentication.getOAuth2Request().getClientId(),
              Stream.of(jsonAccessToken).collect(Collectors.toCollection(HashSet::new))),
          accessWriteOptions, cassandraTemplate.getConverter());
      statementList.add(clientIdToAccessInsert);
    } else {
      clientIdToAccessToken.getoAuth2AccessTokenSet().add(jsonAccessToken);
      Update clientIdToAccessUpdate = CassandraTemplate.createUpdateQuery(ClientIdToAccessToken.TABLE,
          clientIdToAccessToken, accessWriteOptions, cassandraTemplate.getConverter());
      statementList.add(clientIdToAccessUpdate);
    }

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

      Insert refreshTokenToAccessTokenInsert = CassandraTemplate.createInsertQuery(RefreshTokenToAccessToken.TABLE,
          new RefreshTokenToAccessToken(token.getRefreshToken().getValue(), token.getValue()), refreshWriteOptions,
          cassandraTemplate.getConverter());
      statementList.add(refreshTokenToAccessTokenInsert);

    }

    Batch batch = QueryBuilder.batch(statementList.toArray(new RegularStatement[statementList.size()]));
    cassandraTemplate.execute(batch);
  }

  @Override
  public OAuth2AccessToken readAccessToken(String tokenValue) {
    AccessToken accessToken = accessTokenRepository.findOne(tokenValue);
    if (accessToken != null) {
      String jsonOAuth2AccessToken = accessToken.getoAuth2AccessToken();
      OAuth2AccessToken oAuth2AccessToken;
      try {
        oAuth2AccessToken = mapper.readValue(jsonOAuth2AccessToken, OAuth2AccessToken.class);
      } catch (Exception e) {
        logger.error("Error converting json string to OAuth2AccessToken. {}", jsonOAuth2AccessToken);
        throw new RuntimeException(e);
      }
      return oAuth2AccessToken;
    } else {
      return null;
    }
  }

  @Override
  public void removeAccessToken(OAuth2AccessToken token) {
    String tokenValue = token.getValue();
    List<RegularStatement> statementList = prepareRemoveAccessTokenStatements(tokenValue);
    Batch batch = QueryBuilder.batch(statementList.toArray(new RegularStatement[statementList.size()]));
    cassandraTemplate.execute(batch);
  }

  private List<RegularStatement> prepareRemoveAccessTokenStatements(String tokenValue) {
    List<RegularStatement> statementList = new ArrayList<RegularStatement>();

    AccessToken accessToken = accessTokenRepository.findOne(tokenValue);
    if (accessToken != null) {
      Delete accessTokenDelete = CassandraTemplate.createDeleteQuery(AccessToken.TABLE, accessToken, null,
          cassandraTemplate.getConverter());
      statementList.add(accessTokenDelete);
    }

    Authentication authentication = authenticationRepository.findOne(tokenValue);
    if (authentication != null) {
      ByteBuffer bufferedOAuth2Authentication = authentication.getoAuth2Authentication();
      byte[] serializedOAuth2Authentication = new byte[bufferedOAuth2Authentication.remaining()];
      bufferedOAuth2Authentication.get(serializedOAuth2Authentication);

      OAuth2Authentication oAuth2Authentication = SerializationUtils.deserialize(serializedOAuth2Authentication);
      String clientId = oAuth2Authentication.getOAuth2Request().getClientId();

      Delete authenticationDelete = CassandraTemplate.createDeleteQuery(Authentication.TABLE, authentication, null,
          cassandraTemplate.getConverter());
      statementList.add(authenticationDelete);

      AuthenticationToAccessToken authenticationToAccessToken = authenticationToAccessTokenRepository
          .findOne(authenticationKeyGenerator.extractKey(oAuth2Authentication));
      if (authenticationToAccessToken != null) {
        Delete authToAccessDelete = CassandraTemplate.createDeleteQuery(AuthenticationToAccessToken.TABLE,
            authenticationToAccessToken, null, cassandraTemplate.getConverter());
        statementList.add(authToAccessDelete);
      }

      UsernameToAccessToken usernameToAccessToken = usernameToAccessTokenRepository
          .findOne(getApprovalKey(clientId, oAuth2Authentication.getName()));
      if (usernameToAccessToken != null && usernameToAccessToken.getoAuth2AccessTokenSet() != null
          && !usernameToAccessToken.getoAuth2AccessTokenSet().isEmpty()) {
        usernameToAccessToken.getoAuth2AccessTokenSet().remove(accessToken.getoAuth2AccessToken());
        Update unameToAccessUpdate = CassandraTemplate.createUpdateQuery(UsernameToAccessToken.TABLE,
            usernameToAccessToken, null, cassandraTemplate.getConverter());
        statementList.add(unameToAccessUpdate);
      }

      ClientIdToAccessToken clientIdToAccessToken = clientIdToAccessTokenRepository.findOne(clientId);
      if (clientIdToAccessToken != null && clientIdToAccessToken.getoAuth2AccessTokenSet() != null
          && !clientIdToAccessToken.getoAuth2AccessTokenSet().isEmpty()) {
        clientIdToAccessToken.getoAuth2AccessTokenSet().remove(accessToken.getoAuth2AccessToken());
        Update clientIdToAccessUpdate = CassandraTemplate.createUpdateQuery(ClientIdToAccessToken.TABLE,
            clientIdToAccessToken, null, cassandraTemplate.getConverter());
        statementList.add(clientIdToAccessUpdate);
      }
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

    Insert accessInsert = CassandraTemplate.createInsertQuery(RefreshToken.TABLE,
        new RefreshToken(refreshToken.getValue(), bufferedRefreshToken), refreshWriteOptions,
        cassandraTemplate.getConverter());
    statementList.add(accessInsert);

    Insert authInsert = CassandraTemplate.createInsertQuery(RefreshTokenAuthentication.TABLE,
        new RefreshTokenAuthentication(refreshToken.getValue(), bufferedAuthentication), refreshWriteOptions,
        cassandraTemplate.getConverter());
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
    RefreshTokenAuthentication refreshTokenAuthentication = refreshTokenAuthenticationRepository
        .findOne(token.getValue());
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
    statementList.add(prepareDeleteByPrimaryKeyRegularStatement(RefreshToken.class, tokenValue));
    statementList.add(prepareDeleteByPrimaryKeyRegularStatement(RefreshTokenAuthentication.class, tokenValue));
    statementList.add(prepareDeleteByPrimaryKeyRegularStatement(RefreshTokenToAccessToken.class, tokenValue));
    Batch batch = QueryBuilder.batch(statementList.toArray(new RegularStatement[statementList.size()]));
    cassandraTemplate.execute(batch);
  }

  private RegularStatement prepareDeleteByPrimaryKeyRegularStatement(Class<?> repositoryClass, String primaryKeyValue) {
    RegularStatement deleteRegularStatement;
    try {
      deleteRegularStatement = QueryBuilder.delete()
          .from(repositoryClass.getDeclaredField("TABLE").get(null).toString())
          .where(QueryBuilder.eq(cassandraMappingContext.getPersistentEntity(repositoryClass).getIdProperty().getColumnName().toCql(), primaryKeyValue));
    } catch (IllegalArgumentException | IllegalAccessException | NoSuchFieldException | SecurityException e) {
      logger.error("Error preparing delete statement for repository {}.", repositoryClass.getSimpleName());
      throw new RuntimeException(e);
    }
    return deleteRegularStatement;
  }
  
  @Override
  public void removeAccessTokenUsingRefreshToken(OAuth2RefreshToken refreshToken) {
    String tokenValue = refreshToken.getValue();
    RefreshTokenToAccessToken refreshTokenToAccessToken = refreshTokenToAccessTokenRepository.findOne(tokenValue);
    String accessToken = refreshTokenToAccessToken.getAccessTokenKey();
    List<RegularStatement> finalStatementList = new ArrayList<RegularStatement>();
    if (refreshTokenToAccessToken != null) {
      List<RegularStatement> statementList = new ArrayList<RegularStatement>();
      Delete refreshTokenToAccessTokenDelete = CassandraTemplate.createDeleteQuery(RefreshTokenToAccessToken.TABLE,
          refreshTokenToAccessToken, null, cassandraTemplate.getConverter());
      statementList.add(refreshTokenToAccessTokenDelete);
      finalStatementList = Stream
          .concat(statementList.stream(), prepareRemoveAccessTokenStatements(accessToken).stream())
          .collect(Collectors.toList());
    }
    Batch batch = QueryBuilder.batch(finalStatementList.toArray(new RegularStatement[finalStatementList.size()]));
    cassandraTemplate.execute(batch);
  }

  @Override
  public OAuth2AccessToken getAccessToken(OAuth2Authentication authentication) {
    String key = authenticationKeyGenerator.extractKey(authentication);
    AuthenticationToAccessToken authenticationToAccessToken = authenticationToAccessTokenRepository.findOne(key);
    if (authenticationToAccessToken != null) {
      String jsonOAuth2AccessToken = authenticationToAccessToken.getoAuth2AccessToken();
      OAuth2AccessToken oAuth2AccessToken;
      try {
        oAuth2AccessToken = mapper.readValue(jsonOAuth2AccessToken, OAuth2AccessToken.class);
      } catch (Exception e) {
        logger.error("Error converting json string to OAuth2AccessToken. {}", jsonOAuth2AccessToken);
        throw new RuntimeException(e);
      }
      if (oAuth2AccessToken != null
          && !key.equals(authenticationKeyGenerator.extractKey(readAuthentication(oAuth2AccessToken.getValue())))) {
        storeAccessToken(oAuth2AccessToken, authentication);
      }
      return oAuth2AccessToken;
    } else {
      return null;
    }
  }

  @Override
  public Collection<OAuth2AccessToken> findTokensByClientIdAndUserName(String clientId, String userName) {
    String key = getApprovalKey(clientId, userName);
    UsernameToAccessToken usernameToAccessToken = usernameToAccessTokenRepository.findOne(key);
    if (usernameToAccessToken != null) {
      Set<String> jsonOAuth2AccessTokenSet = usernameToAccessToken.getoAuth2AccessTokenSet();
      if (jsonOAuth2AccessTokenSet != null) {
        Set<OAuth2AccessToken> oAuth2AccessTokenSet = new HashSet<OAuth2AccessToken>();
        for (String jsonOAuth2AccessToken : jsonOAuth2AccessTokenSet) {
          OAuth2AccessToken oAuth2AccessToken;
          try {
            oAuth2AccessToken = mapper.readValue(jsonOAuth2AccessToken, OAuth2AccessToken.class);
            oAuth2AccessTokenSet.add(oAuth2AccessToken);
          } catch (Exception e) {
            logger.error("Error converting json string to OAuth2AccessToken. {}", jsonOAuth2AccessToken);
            throw new RuntimeException(e);
          }
        }
        return Collections.<OAuth2AccessToken>unmodifiableCollection(oAuth2AccessTokenSet);
      } else {
        return Collections.<OAuth2AccessToken>emptySet();
      }
    } else {
      return Collections.<OAuth2AccessToken>emptySet();
    }
  }

  @Override
  public Collection<OAuth2AccessToken> findTokensByClientId(String clientId) {
    ClientIdToAccessToken clientIdToAccessToken = clientIdToAccessTokenRepository.findOne(clientId);
    if (clientIdToAccessToken != null) {
      Set<String> jsonOAuth2AccessTokenSet = clientIdToAccessToken.getoAuth2AccessTokenSet();
      if (jsonOAuth2AccessTokenSet != null) {
        Set<OAuth2AccessToken> oAuth2AccessTokenSet = new HashSet<OAuth2AccessToken>();
        for (String jsonOAuth2AccessToken : jsonOAuth2AccessTokenSet) {
          OAuth2AccessToken oAuth2AccessToken;
          try {
            oAuth2AccessToken = mapper.readValue(jsonOAuth2AccessToken, OAuth2AccessToken.class);
            oAuth2AccessTokenSet.add(oAuth2AccessToken);
          } catch (Exception e) {
            logger.error("Error converting json string to OAuth2AccessToken. {}", jsonOAuth2AccessToken);
            throw new RuntimeException(e);
          }
        }
        return Collections.<OAuth2AccessToken>unmodifiableCollection(oAuth2AccessTokenSet);
      } else {
        return Collections.<OAuth2AccessToken>emptySet();
      }
    } else {
      return Collections.<OAuth2AccessToken>emptySet();
    }
  }

  private String getApprovalKey(OAuth2Authentication authentication) {
    String userName = authentication.getUserAuthentication() == null ? ""
        : authentication.getUserAuthentication().getName();
    return getApprovalKey(authentication.getOAuth2Request().getClientId(), userName);
  }

  private String getApprovalKey(String clientId, String userName) {
    return clientId + (userName == null ? "" : ":" + userName);
  }

}
