/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cryptopals.set1;

import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author balsfull
 */
public class Challenge3 {
    
    private static final String encoded = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    private static final String normalAlpha = "[a-zA-Z.,!?:()\" ]";
    
    public static void decryptHex(String encrypted) {
        byte[] encodedBytes = Challenge2.hexStringToByteArray(encrypted);
        for(byte b = 0; b < Byte.MAX_VALUE; b++) {
            byte[] decodedBytes = Challenge2.xor(encodedBytes, new byte[]{b});
            String decodedString = new String(decodedBytes);
            if(isPotentiallyCorrect(decodedString)) {
                System.out.println(((char)b) + ": " + decodedString);
            }
        }
    }
    
    public static Map<Character, String> bruteForce(String encrypted) {
        Map<Character, String> solutions = new HashMap<>();
        byte[] encodedBytes = encrypted.getBytes();
        for(byte b = 0; b < Byte.MAX_VALUE; b++) {
            byte[] decodedBytes = Challenge2.xor(encodedBytes, new byte[]{b});
            String decodedString = new String(decodedBytes);
            //System.out.println(b + ", " + getQuality(decodedString) + ": " + decodedString.replaceAll("\n", ""));
            if(isPotentiallyCorrect(decodedString)) {
                System.out.println(b + ", " + getQuality(decodedString) + ": " + decodedString.replaceAll("\n", ""));
                solutions.put((char)b, decodedString);
            }
        }
        return solutions;
    }
    
    private static double getQuality(String s) {
        return s.length() / Math.max(s.replaceAll(normalAlpha, "").length(), 0.5);
    }
    
    public static boolean isPotentiallyCorrect(String s) {
        return getQuality(s) > 10;
    }
}
