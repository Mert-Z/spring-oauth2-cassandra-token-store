package mertz.security.oauth2.provider.token.store.cassandra.repo;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import mertz.security.oauth2.provider.token.store.cassandra.model.AccessToken;

@Repository
public interface AccessTokenRepository extends CrudRepository<AccessToken, String> {

}
