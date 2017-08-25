package mertz.security.oauth2.provider.token.store.cassandra;

import org.junit.Before;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.ConfigFileApplicationContextInitializer;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.cassandra.core.CassandraOperations;
import org.springframework.data.cassandra.mapping.CassandraMappingContext;
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

}
