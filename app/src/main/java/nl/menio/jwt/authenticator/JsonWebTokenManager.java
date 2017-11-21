package nl.menio.jwt.authenticator;

import android.support.annotation.Nullable;

public interface JsonWebTokenManager {

    /**
     * Sets the token after refreshing it.
     * @param token the new token.
     */
    void setToken(@Nullable final String token);
}
