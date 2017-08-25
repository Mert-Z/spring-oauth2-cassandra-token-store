package mertz.security.oauth2.provider.token.store.cassandra.model;

import java.nio.ByteBuffer;

import org.springframework.data.cassandra.mapping.PrimaryKey;
import org.springframework.data.cassandra.mapping.Table;

@Table(value = RefreshTokenAuthentication.TABLE)
public class RefreshTokenAuthentication {

    public static final String TABLE = "refresh_auth";

    @PrimaryKey
    private String     tokenId;

    // Serialized
    private ByteBuffer oAuth2Authentication;

    public RefreshTokenAuthentication(String tokenId, ByteBuffer oAuth2Authentication) {
        super();
        this.tokenId = tokenId;
        this.oAuth2Authentication = oAuth2Authentication;
    }

    public final String getTokenId() {
        return tokenId;
    }

    public final ByteBuffer getoAuth2Authentication() {
        return oAuth2Authentication;
    }

    @Override
    public String toString() {
        return "RefreshTokenAuthentication [tokenId=" + tokenId + "]";
    }

}
