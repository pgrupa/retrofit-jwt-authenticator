package nl.menio.jwt.authenticator;

import android.support.annotation.Nullable;

public abstract class JsonWebTokenRequest {

    /**
     * Gets the token.
     * @return the token.
     */
    @Nullable
    public abstract String getToken();
}
