package nl.menio.jwt.authenticator;

import android.support.annotation.Nullable;

public interface JsonWebTokenProvider {

    /**
     * Returns the token which is used to refresh the token.
     * @return the token or null
     */
    @Nullable
    String getToken();
}
