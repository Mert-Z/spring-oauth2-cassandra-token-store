package mertz.security.oauth2.provider.token.store.cassandra.model;

import org.springframework.data.cassandra.mapping.PrimaryKey;
import org.springframework.data.cassandra.mapping.Table;

@Table(value = AccessToken.TABLE)
public class AccessToken {

    public static final String TABLE = "access";

    @PrimaryKey
    private String             tokenId;

    // JSON
    private String             oAuth2AccessToken;

    public AccessToken(String tokenId, String oAuth2AccessToken) {
        super();
        this.tokenId = tokenId;
        this.oAuth2AccessToken = oAuth2AccessToken;
    }

    public final String getTokenId() {
        return tokenId;
    }

    public final String getoAuth2AccessToken() {
        return oAuth2AccessToken;
    }

    @Override
    public String toString() {
        return "AccessToken [tokenId=" + tokenId + ", oAuth2AccessToken=" + oAuth2AccessToken + "]";
    }

}
