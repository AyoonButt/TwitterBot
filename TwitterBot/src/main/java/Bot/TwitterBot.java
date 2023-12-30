package Bot;

import com.twitter.clientlib.api.TwitterApi;
import com.twitter.clientlib.TwitterCredentialsOAuth2;
import com.twitter.clientlib.ApiException;
import com.twitter.clientlib.model.TweetCreateRequest;
import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.core.builder.api.DefaultApi20;
import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.oauth.OAuth20Service;
import spark.Spark;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;

public class TwitterBot {

    private TwitterApi apiInstanceJava;
    private List<String> tweets;
    private TwitterCredentialsOAuth2 credentials;
    private OAuth20Service oauth20Service;
    private OAuth2AccessToken accessToken;
    private String authorizationCodeReceived; // Added instance variable

    public TwitterBot(String clientId, String clientSecret, String accessToken, String refreshToken) {
        this.credentials = new TwitterCredentialsOAuth2(clientId, clientSecret, accessToken, refreshToken);
        authenticateTwitterApi();
        startHttpServer();
        tweets = new ArrayList<>();
        loadTweetsFromFile("C:\\Users\\ayoon\\projects\\TwitterBot-1\\TwitterBot\\src\\main\\resources\\tweets.txt");
    }

    public static void main(String[] args) {
        // Use your actual client ID, client secret, access token, and refresh token
        String clientId = "eWdaSkU5RVNLUWpsWmpnWEs2ZG46MTpjaQ";
        String clientSecret = "jipTcKM3lCykBF2alFXe0AW7hX0_BNYDFJ6mhX9IkVjlNUgJhB";
        String accessToken = "1735157452063047680-KAfYOYeMKkmdfQE0SSZQt8pQxB8HaH";
        String refreshToken = "False";

        TwitterBot twitterBot = new TwitterBot(clientId, clientSecret, accessToken, refreshToken);
        twitterBot.initiateOAuth2();
        twitterBot.tweetQuotes();
    }

    private void loadTweetsFromFile(String fileName) {
        try {
            tweets = Files.readAllLines(Paths.get(fileName));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void authenticateTwitterApi() {
        apiInstanceJava = new TwitterApi(credentials);
    }

    private void startHttpServer() {
        Spark.port(4567);

        Spark.post("/authorize", (request, response) -> {
            authorizationCodeReceived = request.queryParams("code");
            System.out.println("Received authorization code: " + authorizationCodeReceived);

            // Perform any additional tasks if needed

            response.status(200);
            return "Authorization code received successfully";
        });
    }

    private void initiateOAuth2() {
        oauth20Service = new ServiceBuilder("your_client_id")
                .apiSecret("your_client_secret")
                .defaultScope("read write")
                .callback("https://ayoonbutt.github.io/callback")
                .build(new CustomTwitterApi20());
 
        // Redirect the user to the authorization URL
        String authorizationUrl = oauth20Service.getAuthorizationUrl();
        System.out.println("Authorization URL: " + authorizationUrl);

        // Here, you would typically direct the user to the authorization URL (e.g., by opening a browser)
        // and wait for the user to grant permission. The authorization code will be received on the callback.

        // Once authorization code is received, call authenticateOAuth2 with the stored authorization code
        authenticateOAuth2("your_client_id", "your_client_secret", authorizationCodeReceived);
    }

    private void authenticateOAuth2(String clientId, String clientSecret, String authorizationCode) {
        // Initialize oauth20Service before using it
        if (oauth20Service == null) {
            System.err.println("OAuth 2.0 service is not initialized.");
            return;
        }

        try {
            accessToken = oauth20Service.getAccessToken(authorizationCode);
        } catch (IOException | InterruptedException | ExecutionException e) {
            e.printStackTrace();
        }

        // Print the obtained access token
        System.out.println("Access Token: " + accessToken.getAccessToken());
    }

    private void tweetQuotes() {
        for (String tweet : tweets) {
            try {
                createAndSendTweet(tweet);
                System.out.println("Successfully tweeted: " + tweet);
            } catch (ApiException e) {
                handleTweetError(tweet, e);
            }

            sleepForInterval(1800000);
        }
    }

    private void createAndSendTweet(String tweetText) throws ApiException {
        TweetCreateRequest tweetCreateRequest = new TweetCreateRequest();
        tweetCreateRequest.setText(tweetText);

        TwitterApi apiInstanceWithToken = new TwitterApi(new TwitterCredentialsOAuth2(
                "your_client_id", "your_client_secret", accessToken.getAccessToken(), accessToken.getRefreshToken()));

        apiInstanceWithToken.tweets().createTweet(tweetCreateRequest).execute();
    }

    private void handleTweetError(String tweet, ApiException e) {
        System.err.println("Error tweeting: " + tweet);
        e.printStackTrace();
    }

    private void sleepForInterval(long milliseconds) {
        try {
            System.out.println("Sleeping for " + milliseconds / 60000 + " minutes...");
            Thread.sleep(milliseconds);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    public class CustomTwitterApi20 extends DefaultApi20 {

        @Override
        public String getAccessTokenEndpoint() {
            return "https://api.twitter.com/oauth/access_token";
        }

        @Override
        protected String getAuthorizationBaseUrl() {
            return "https://api.twitter.com/oauth/authenticate";
        }
    }
}



