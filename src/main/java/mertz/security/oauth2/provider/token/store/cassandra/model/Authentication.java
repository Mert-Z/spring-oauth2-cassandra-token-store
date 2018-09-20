package mertz.security.oauth2.provider.token.store.cassandra.model;

import org.springframework.data.cassandra.core.mapping.PrimaryKey;
import org.springframework.data.cassandra.core.mapping.Table;

import java.nio.ByteBuffer;

@Table(value = Authentication.TABLE)
public class Authentication {

    public static final String TABLE = "auth";

    @PrimaryKey
    private String     tokenId;

    // Serialized
    private ByteBuffer oAuth2Authentication;

    public Authentication(String tokenId, ByteBuffer oAuth2Authentication) {
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
        return "Authentication [tokenId=" + tokenId + "]";
    }

}
