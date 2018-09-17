package mertz.security.oauth2.provider.token.store.cassandra.model;


import org.springframework.data.cassandra.core.mapping.PrimaryKey;
import org.springframework.data.cassandra.core.mapping.Table;

@Table(value = AuthenticationToAccessToken.TABLE)
public class AuthenticationToAccessToken {

    public static final String TABLE = "auth_to_access";

    @PrimaryKey
    private String key;

    // JSON
    private String oAuth2AccessToken;

    public AuthenticationToAccessToken(String key, String oAuth2AccessToken) {
        super();
        this.key = key;
        this.oAuth2AccessToken = oAuth2AccessToken;
    }

    public final String getKey() {
        return key;
    }

    public final String getoAuth2AccessToken() {
        return oAuth2AccessToken;
    }

    @Override
    public String toString() {
        return "AuthenticationToAccessToken [key=" + key + ", oAuth2AccessToken=" + oAuth2AccessToken + "]";
    }

}
