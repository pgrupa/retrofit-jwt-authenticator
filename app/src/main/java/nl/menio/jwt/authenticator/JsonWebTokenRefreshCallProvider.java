package nl.menio.jwt.authenticator;

import android.support.annotation.NonNull;

import retrofit2.Call;

public interface JsonWebTokenRefreshCallProvider<T extends JsonWebTokenResponse> {

    /**
     * Returns the call that can be used to refresh the web token.
     * @param requestData the request data.
     * @return the call.
     */
    Call<T> getJsonWebTokenRefreshCall(@NonNull JsonWebTokenRequest requestData);
}
