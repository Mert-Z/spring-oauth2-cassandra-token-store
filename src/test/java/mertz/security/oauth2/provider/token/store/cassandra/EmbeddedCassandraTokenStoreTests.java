package mertz.security.oauth2.provider.token.store.cassandra;

import org.cassandraunit.spring.CassandraDataSet;
import org.cassandraunit.spring.CassandraUnitDependencyInjectionTestExecutionListener;
import org.cassandraunit.spring.EmbeddedCassandra;
import org.junit.runner.RunWith;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestExecutionListeners;
import org.springframework.test.context.TestExecutionListeners.MergeMode;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
@TestExecutionListeners(
    listeners = CassandraUnitDependencyInjectionTestExecutionListener.class, 
    mergeMode = MergeMode.MERGE_WITH_DEFAULTS
)
@EmbeddedCassandra
@CassandraDataSet(keyspace = "${spring.data.cassandra.keyspace-name}")
@ActiveProfiles(profiles = "embeddedcassandra", inheritProfiles = false)
public class EmbeddedCassandraTokenStoreTests extends CassandraTokenStoreTests {

}
