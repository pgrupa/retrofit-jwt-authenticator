package nl.menio.jwt.authenticator;

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.util.Log;

import java.io.IOException;
import java.util.concurrent.Semaphore;

import okhttp3.Authenticator;
import okhttp3.Request;
import okhttp3.Route;
import retrofit2.Call;
import retrofit2.Response;

public class JwtAuthenticator<T extends JsonWebTokenResponse> implements Authenticator {

    private static final String TAG = JwtAuthenticator.class.getSimpleName();
    private static final int SEMAPHORE_PERMITS = 1;
    private static final boolean SEMAPHORE_FAIR = true;
    private static final Semaphore LOCK = new Semaphore(SEMAPHORE_PERMITS, SEMAPHORE_FAIR);
    private static final String DEFAULT_AUTHORIZATION_HEADER = "Authorization";
    private static final String DEFAULT_AUTHORIZATION_TYPE = "Bearer";

    private JsonWebTokenRequestProvider mJsonWebTokenRequestProvider = null;
    private JsonWebTokenManager mJsonWebTokenManager = null;
    private JsonWebTokenRefreshCallProvider<T> mJsonWebTokenRefreshCallProvider = null;
    private boolean mIsLocking = true;
    private String mAuthorizationHeader = DEFAULT_AUTHORIZATION_HEADER;
    private String mAuthorizationType = DEFAULT_AUTHORIZATION_TYPE;

    private JwtAuthenticator() {
        // Hides the public constructor
    }

    private void setJsonWebTokenRequestProvider(@NonNull final JsonWebTokenRequestProvider provider) {
        mJsonWebTokenRequestProvider = provider;
    }

    private void setJsonWebTokenManager(@NonNull final JsonWebTokenManager manager) {
        mJsonWebTokenManager = manager;
    }

    private void setJsonWebTokenRefreshCallProvider(@NonNull final JsonWebTokenRefreshCallProvider<T> provider) {
        mJsonWebTokenRefreshCallProvider = provider;
    }

    private void setLocking(final boolean isLocking) {
        mIsLocking = isLocking;
    }

    private void checkConfiguration() {
        if (mJsonWebTokenRequestProvider == null) {
            throw new IllegalStateException("An implementation of a " + JsonWebTokenProvider.class.getCanonicalName() + " must be provided");
        } else if (mJsonWebTokenManager == null) {
            throw new IllegalStateException("An implementation of a " + JsonWebTokenManager.class.getCanonicalName() + " must be provided");
        } else if (mAuthorizationHeader == null) {
            throw new IllegalStateException("The authorization header must be set, default value: " + DEFAULT_AUTHORIZATION_HEADER);
        } else if (mAuthorizationType == null) {
            throw new IllegalStateException("The authorization type must be set, default value: " + DEFAULT_AUTHORIZATION_TYPE);
        }
    }

    @Nullable
    @Override
    public Request authenticate(@NonNull final Route route, @NonNull final okhttp3.Response response) throws IOException {

        // Check the configuration first
        checkConfiguration();

        // First wait for the semaphore. Make sure to release the lock on any error so we do not
        // block the authenticator.
        if (mIsLocking) {
            try {
                LOCK.acquire();
            } catch (InterruptedException e) {
                LOCK.release();
                return null;
            }
        }

        // Refresh the token
        final JsonWebTokenRequest requestData = mJsonWebTokenRequestProvider.getJsonWebTokenRequest();
        final String token = requestData.getToken();
        if (token == null) {
            Log.e(TAG, "No refresh token: null");
            release();
            return null;
        }
        final Call<T> call = mJsonWebTokenRefreshCallProvider.getJsonWebTokenRefreshCall(requestData);
        final Response<T> refreshResponse = call.execute();
        if (refreshResponse != null) {
            final JsonWebTokenResponse refreshResponseData = refreshResponse.body();
            if (refreshResponseData == null) {
                Log.e(TAG, "Invalid response data: null");
                release();
                return null;
            }
            final String newToken = refreshResponseData.getToken();
            if (newToken == null) {
                Log.e(TAG, "Invalid token: null");
                release();
                return null;
            }
            mJsonWebTokenManager.setToken(newToken);

            // Rewrite the header with the new token
            release();
            return response.request().newBuilder()
                    .header(mAuthorizationHeader, mAuthorizationType + "" + newToken)
                    .build();
        }
        release();
        return null;
    }

    private void release() {
        if (mIsLocking) {
            LOCK.release();
        }
    }

    public class Builder<T extends JsonWebTokenResponse> {

        private final JwtAuthenticator<T> instance;

        public Builder() {
            instance = new JwtAuthenticator<>();
        }

        /**
         * Sets the Json Web Token provider which provides the token to refresh. Setting a non-null
         * provider is required.
         * @param provider the provider to use.
         * @return this builder.
         */
        public Builder<T> setJsonWebTokenRequestProvider(@NonNull final JsonWebTokenRequestProvider provider) {
            instance.setJsonWebTokenRequestProvider(provider);
            return this;
        }

        /**
         * Sets the Json Web Token manager which accepts a newly refreshed token and saves is as it
         * pleases. Setting a non-null manager is required.
         * @param manager the manager to use.
         * @return this builder.
         */
        public Builder<T> setJsonWebTokenManager(@NonNull final JsonWebTokenManager manager) {
            instance.setJsonWebTokenManager(manager);
            return this;
        }

        /**
         * Sets the provider of the Call instance that is used to refresh tokens. Setting a non-null
         * provider is required.
         * @param provider the provider to use.
         * @return this builder.
         */
        public Builder<T> setJsonWebTokenRefreshCallProvider(@NonNull final JsonWebTokenRefreshCallProvider<T> provider) {
            instance.setJsonWebTokenRefreshCallProvider(provider);
            return this;
        }

        /**
         * Sets wheter this authenticator is locking. If you only use one client and one Retrofit
         * instance, you can set this to false, otherwise set it to true. This makes sure that when
         * using multiple instances of the authenticator, the refresh is performed only once. The
         * locking mechanism is provided by a Semaphore.
         * @param isLocking whether this authenticator should be locking or not.
         * @return this builder.
         */
        public Builder<T> setLocking(final boolean isLocking) {
            instance.setLocking(isLocking);
            return this;
        }
    }
}
