# Cassandra OAuth2 Token Store for Spring Security OAuth2

Implementation of [org.springframework.security.oauth2.provider.token.TokenStore](https://github.com/spring-projects/spring-security-oauth/blob/master/spring-security-oauth2/src/main/java/org/springframework/security/oauth2/provider/token/TokenStore.java) backed by Cassandra **(which can be executed on multi node cluster)**.

## Getting Started

Implementation follows similar data model with [org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore](https://github.com/spring-projects/spring-security-oauth/blob/master/spring-security-oauth2/src/main/java/org/springframework/security/oauth2/provider/token/store/redis/RedisTokenStore.java) in persisting OAuth2 tokens in Cassandra.

[CassandraTokenStore](https://github.com/Mert-Z/spring-oauth2-cassandra-token-store/blob/master/src/main/java/mertz/security/oauth2/provider/token/store/cassandra/CassandraTokenStore.java) includes some enhancements on top of [RedisTokenStore](https://github.com/spring-projects/spring-security-oauth/blob/master/spring-security-oauth2/src/main/java/org/springframework/security/oauth2/provider/token/store/redis/RedisTokenStore.java) such as;
* Use of Cassandra batches to achieve atomicity while persisting OAuth2 tokens
* Removal of unnecessary ACCESS_TO_REFRESH tuple which is used to store access token - refresh token in [RedisTokenStore](https://github.com/spring-projects/spring-security-oauth/blob/master/spring-security-oauth2/src/main/java/org/springframework/security/oauth2/provider/token/store/redis/RedisTokenStore.java). (See [spring-security-oauth#1138](https://github.com/spring-projects/spring-security-oauth/issues/1138))

### Prerequisites
Dependencies listed below;
* **spring-boot-starter-data-cassandra** provides Cassandra interface for performing CRUD on OAuth tokens
* **spring-security-oauth2** provides OAuth 2.0 API
* **jackson-databind** provides ObjectMapper API which is used to serialize OAuth tokens before storing them in Cassandra

### Installing
Implementation follows the same directory structure with token store examples provided by [spring-security-oauth](https://github.com/spring-projects/spring-security-oauth/tree/master/spring-security-oauth2/src/main/java/org/springframework/security/oauth2/provider/token/store). You can simply copy this repository and autowire *CassandraTokenStore* into [AuthorizationServerEndpointsConfigurer.tokenStore(TokenStore)](https://docs.spring.io/spring-security/oauth/apidocs/org/springframework/security/oauth2/config/annotation/web/configurers/AuthorizationServerEndpointsConfigurer.html)
```
@Configuration
public class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private TokenStore cassandraTokenStore;

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints.tokenStore(tokenStore);
    }
}
```

## Running the tests
CassandraTokenStore is tested using [spring-security-oauth2 token store tests](https://github.com/spring-projects/spring-security-oauth/blob/master/spring-security-oauth2/src/test/java/org/springframework/security/oauth2/provider/token/store/TokenStoreBaseTests.java).

[CassandraTokenStoreTests](https://github.com/Mert-Z/spring-oauth2-cassandra-token-store/blob/master/src/test/java/mertz/security/oauth2/provider/token/store/cassandra/CassandraTokenStoreTests.java) initializes a test context which looks for connecting to an external standalone Cassandra instance listening connections on *localhost:9042*.

[EmbeddedCassandraTokenStoreTests](https://github.com/Mert-Z/spring-oauth2-cassandra-token-store/blob/master/src/test/java/mertz/security/oauth2/provider/token/store/cassandra/EmbeddedCassandraTokenStoreTests.java) extends *CassandraTokenStoreTests* for providing a test context which starts an embedded Cassandra instance listening connections on *localhost:9142*. Embedded Cassandra is provided by [Spring for Cassandra unit](https://github.com/jsevellec/cassandra-unit/wiki/Spring-for-Cassandra-unit).

EmbeddedCassandraTokenStoreTests can be executed as shown below;
```
gradlew.bat test --tests mertz.security.oauth2.provider.token.store.cassandra.EmbeddedCassandraTokenStoreTests
```

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details
