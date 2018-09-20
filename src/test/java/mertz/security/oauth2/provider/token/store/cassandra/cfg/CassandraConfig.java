package mertz.security.oauth2.provider.token.store.cassandra.cfg;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.cassandra.config.AbstractCassandraConfiguration;
import org.springframework.data.cassandra.config.SchemaAction;
import org.springframework.data.cassandra.core.cql.keyspace.CreateKeyspaceSpecification;
import org.springframework.data.cassandra.repository.config.EnableCassandraRepositories;

@Configuration
@EnableCassandraRepositories(basePackages = "mertz.security.oauth2.provider.token.store.cassandra.repo")
public class CassandraConfig extends AbstractCassandraConfiguration {

  private @Value("${spring.data.cassandra.keyspace-name}") String keyspaceName;
  private @Value("${spring.data.cassandra.contact-points}") String contactPoints;
  private @Value("${spring.data.cassandra.port}") int port;

  @Override
  protected List<CreateKeyspaceSpecification> getKeyspaceCreations() {
    CreateKeyspaceSpecification createKeyspaceSpecification = CreateKeyspaceSpecification.createKeyspace(keyspaceName).withSimpleReplication(1).ifNotExists(true);
    List<CreateKeyspaceSpecification> keyspaceList = new ArrayList<CreateKeyspaceSpecification>();
    keyspaceList.add(createKeyspaceSpecification);
    return keyspaceList;
  }

  @Override
  public SchemaAction getSchemaAction() {
    return SchemaAction.RECREATE;
  }

  @Override
  public String[] getEntityBasePackages() {
    return new String[] { "mertz.security.oauth2.provider.token.store.cassandra.model" };
  }

  @Override
  protected String getKeyspaceName() {
    return keyspaceName;
  }

  @Override
  protected String getContactPoints() {
    return contactPoints;
  }

  @Override
  protected int getPort() {
    return port;
  }

}
