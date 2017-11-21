package nl.menio.jwt.authenticator;

public interface JsonWebTokenRequestProvider {

    /**
     * Provides the object with the needed data to perform the refresh request.
     * @return the object.
     */
    JsonWebTokenRequest getJsonWebTokenRequest();
}
