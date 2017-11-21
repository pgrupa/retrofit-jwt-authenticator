package nl.menio.jwt.authenticator;

import android.support.annotation.Nullable;

public abstract class JsonWebTokenResponse {

    /**
     * Returns the Json Web Token.
     * @return the token.
     */
    @Nullable
    public abstract String getToken();
}
