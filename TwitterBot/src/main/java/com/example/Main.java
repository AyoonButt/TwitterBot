package com.example;
import twitter4j.Status;
import twitter4j.Twitter;
import twitter4j.TwitterException;
import twitter4j.TwitterFactory;

import java.io.*;
import java.nio.charset.Charset;

public class Main {

    public static void main(String[] args) {
        tweetQuotes();
    }

    private static void tweetQuotes() {
        String line;
        try {
                InputStream fis = new FileInputStream("C:/Users/ayoon/projects/TwitterBot/src/main/resources/tweets.txt");
                InputStreamReader isr = new InputStreamReader(fis, Charset.forName("Cp1252"));
                BufferedReader br = new BufferedReader(isr);

                while ((line = br.readLine()) != null) {
                    sendTweetAPI(line);
                    System.out.println("Tweeting: " + line + "...");

                    try {
                        System.out.println("Sleeping for 30 minutes...");
                        Thread.sleep(1800000); // every 30 minutes
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }

                }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void sendTweetAPI(String line) {
        try {
            Twitter twitter = new TwitterFactory().getInstance();
            Status status;
            status = twitter.updateStatus(line);
            System.out.println(status);
        }
        catch (TwitterException te) {
            te.printStackTrace();
            System.out.println("Failed to get timeline: " + te.getMessage());
            System.exit(-1);
        }
    }
}