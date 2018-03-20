package com.fiendfyre.AdHell2.utils;

/**
 * Created by Matt on 19/01/2018.
 */
import android.util.Log;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BlockUrlPatternsMatch {


    public static boolean wildcardValid (String domain){

        // Wildcard pattern to match
        String wildcardPattern = "(?i)^([\\*]?)([A-Z0-9-_.]+)([\\*]?)$";

        // Create a pattern object
        Pattern r = Pattern.compile(wildcardPattern);

        // Create a matcher object
        Matcher m = r.matcher(domain);

        // True or false
        boolean matchResult = m.matches();

        return matchResult;
    }

    public static boolean domainValid (String domain){

        // Domain pattern to match
        String domainPattern = "(?i)(?=^.{4,253}$)(^((?!-)[a-z0-9-]{1,63}(?<!-)\\.)+[a-z]{2,63}$)";

        // Create a pattern object
        Pattern r = Pattern.compile(domainPattern);

        // Create a matcher object
        Matcher m = r.matcher(domain);

        // True or false
        boolean matchResult = m.matches();

        return matchResult;
    }

}
