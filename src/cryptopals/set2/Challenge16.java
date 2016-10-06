/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cryptopals.set2;

import static cryptopals.set1.Challenge2.xor;
import cryptopals.set1.Challenge7;
import cryptopals.set1.Challenge7.Message;
import cryptopals.set1.Challenge7.Message.Counter;
import cryptopals.set1.Challenge7.Mode;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

/**
 *
 * @author balsfull
 */
public class Challenge16 {

    private static final Random random = new Random(123123);
    private static final byte[] key;
    private static final byte[] iv;
    
    //CBC
//    public static void main(String[] args) {
//        ForumManager fm = new ForumManager(key, iv);
//        byte[] encoded = fm.createEcodedUserData(new String("0123456789ABCDEF:admin<true".getBytes()));
//        encoded[32]++;
//        encoded[38]++;
//        System.out.println(fm.isAdminData(encoded));
//    }

    private static class ForumManager {

        private static final String ADMIN = "admin";
        private static final String PREPEND = "comment1=cooking%20MCs;userdata=";
        private static final String APPEND = ";comment2=%20like%20a%20pound%20of%20bacon";
        private byte[] key, iv;
        
        public ForumManager(byte[] key, byte[] iv) {
            this.key = key;
            this.iv = iv;
        }

        public byte[] createEcodedUserData(String userdata) {
            String fulldata = PREPEND + sanitize(userdata) + APPEND;
            System.out.println(fulldata);
            Message message = new Message(fulldata.getBytes());
            message.encrypt(key, iv, Counter.getDefault(8), Mode.CTR);
            return message.getData();
        }

        public boolean isAdminData(byte[] ciphertext) {
            Message message = new Message(ciphertext);
            message.decrypt(key, iv, Counter.getDefault(8), Mode.CTR);
            String dataString = new String(message.getData());
            Map<String, String> inputData = parseInputData(dataString);
            if(!inputData.containsKey(ADMIN)) {
                return false;
            }
            return "true".equals(inputData.get(ADMIN));
        }

        private String sanitize(String input) {
            return input.replaceAll(";", "&#59;").replaceAll("=", "&#61");
        }

        private Map<String, String> parseInputData(String input) {
            String[] variables = input.split(";");

            Map<String, String> result = new HashMap<>();
            for(String variable : variables) {
                addValue(result, variable);
            }

            return result;
        }

        private void addValue(Map<String, String> result, String variable) {
            String[] split = variable.split("=");
            result.put(split[0], split[1]);
        }
    }
    
    static {
        key = new byte[16];
        iv = new byte[8];
        random.nextBytes(key);
        random.nextBytes(iv);
    }
}
