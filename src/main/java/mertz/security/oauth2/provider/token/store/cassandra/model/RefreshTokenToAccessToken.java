package mertz.security.oauth2.provider.token.store.cassandra.model;

import org.springframework.data.cassandra.mapping.PrimaryKey;
import org.springframework.data.cassandra.mapping.Table;

@Table(value = RefreshTokenToAccessToken.TABLE)
public class RefreshTokenToAccessToken {

    public static final String TABLE = "refresh_to_access";

    @PrimaryKey
    private String refreshTokenKey;

    private String accessTokenKey;

    public RefreshTokenToAccessToken(String refreshTokenKey, String accessTokenKey) {
        super();
        this.refreshTokenKey = refreshTokenKey;
        this.accessTokenKey = accessTokenKey;
    }

    public final String getRefreshTokenKey() {
        return refreshTokenKey;
    }

    public final String getAccessTokenKey() {
        return accessTokenKey;
    }

    @Override
    public String toString() {
        return "RefreshTokenToAccessToken[refreshTokenKey=" + refreshTokenKey + ", accessTokenKey=" + accessTokenKey + "]";
    }
}
