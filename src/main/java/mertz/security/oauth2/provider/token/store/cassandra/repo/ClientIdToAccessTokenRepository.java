package mertz.security.oauth2.provider.token.store.cassandra.repo;

import java.util.List;
import java.util.Optional;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import mertz.security.oauth2.provider.token.store.cassandra.model.ClientIdToAccessToken;

@Repository
public interface ClientIdToAccessTokenRepository extends CrudRepository<ClientIdToAccessToken, String> {

  Optional<ClientIdToAccessToken> findByKeyAndOAuth2AccessToken(String key, String oAuth2AccessToken);

  Optional<List<ClientIdToAccessToken>> findByKey(String key);

}
