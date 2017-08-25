package mertz.security.oauth2.provider.token.store.cassandra.model;

import java.util.Set;

import org.springframework.data.cassandra.mapping.PrimaryKey;
import org.springframework.data.cassandra.mapping.Table;

@Table(value = UsernameToAccessToken.TABLE)
public class UsernameToAccessToken {

    public static final String TABLE = "uname_to_access";

    @PrimaryKey
    private String      key;

    // Set of JSON
    private Set<String> oAuth2AccessTokenSet;

    public UsernameToAccessToken(String key, Set<String> oAuth2AccessTokenSet) {
        super();
        this.key = key;
        this.oAuth2AccessTokenSet = oAuth2AccessTokenSet;
    }

    public final String getKey() {
        return key;
    }

    public final Set<String> getoAuth2AccessTokenSet() {
        return oAuth2AccessTokenSet;
    }

    @Override
    public String toString() {
        return "UsernameToAccessToken [key=" + key + ", oAuth2AccessTokenSet=" + oAuth2AccessTokenSet + "]";
    }

}
