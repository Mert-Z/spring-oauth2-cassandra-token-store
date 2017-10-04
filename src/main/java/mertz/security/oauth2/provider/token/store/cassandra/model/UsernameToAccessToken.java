package mertz.security.oauth2.provider.token.store.cassandra.model;

import org.springframework.cassandra.core.PrimaryKeyType;
import org.springframework.data.cassandra.mapping.PrimaryKeyColumn;
import org.springframework.data.cassandra.mapping.Table;

@Table(value = UsernameToAccessToken.TABLE)
public class UsernameToAccessToken {

    public static final String TABLE = "uname_to_access";

    @PrimaryKeyColumn(name = "key", ordinal = 0, type = PrimaryKeyType.PARTITIONED)
    private String      key;

    // Set of JSON
    @PrimaryKeyColumn(name = "oAuth2AccessToken", ordinal = 1, type = PrimaryKeyType.CLUSTERED)
    private String oAuth2AccessToken;

    public UsernameToAccessToken(String key, String oAuth2AccessToken) {
        super();
        this.key = key;
        this.oAuth2AccessToken = oAuth2AccessToken;
    }

    public final String getKey() {
        return key;
    }

    public final String getOAuth2AccessToken() {
        return oAuth2AccessToken;
    }

    @Override
    public String toString() {
        return "UsernameToAccessToken [key=" + key + ", oAuth2AccessToken=" + oAuth2AccessToken + "]";
    }

}
