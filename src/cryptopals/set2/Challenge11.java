/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cryptopals.set2;

import static cryptopals.set1.Challenge2.byteArrayToHexString;
import cryptopals.set1.Challenge7.Message;
import cryptopals.set1.Challenge7.Mode;
import java.util.Random;

/**
 *
 * @author balsfull
 */
public class Challenge11 {

    private static final Random random = new Random();

//    public static void main(String[] args) {
//        byte[] data = generateTestData(4);
//        System.out.println(getMode(encryptRandomly(data)));
//    }

    public static Mode getMode(byte[] data) {
        data = Challenge12.append(generateTestData(5), data);
        byte[] genericKey = getRandomKey();
        Message message = new Message(data);
        message.decrypt(genericKey, Mode.ECB);
        String result = byteArrayToHexString(data);
        for(String hexString : result.split("(?<=\\G.{32})")) {
            int length = (result.length() - result.replace(hexString, "").length()) / hexString.length();
            if(length > 1) {
                return Mode.ECB;
            }
        }
        return Mode.CBC;
    }

    public static byte[] generateTestData(int repetitions) {
        byte[] uniqueSequence = new byte[16];
        random.nextBytes(uniqueSequence);
        byte[] result = new byte[(uniqueSequence.length + 1) * uniqueSequence.length * repetitions];
        for(int i = 0; i < uniqueSequence.length * repetitions; i++) {
            System.arraycopy(uniqueSequence, 0, result, (uniqueSequence.length + 1) * i, uniqueSequence.length);
        }
        return result;
    }

    private static byte[] encryptRandomly(byte[] message) {
        byte[] before = new byte[random.nextInt(5) + 5], after = new byte[random.nextInt(5) + 5];
        byte[] newMsg = new byte[message.length + before.length + after.length];
        random.nextBytes(before);
        random.nextBytes(after);
        System.arraycopy(message, 0, newMsg, before.length, message.length);
        System.arraycopy(before, 0, newMsg, 0, before.length);
        System.arraycopy(after, 0, newMsg, before.length + message.length, after.length);
        Message m = new Message(newMsg);
        byte[] key = getRandomKey();
        if(random.nextBoolean()) {//ECB
            m.encrypt(key, Mode.ECB);
        }
        else {//CBC
            byte[] iv = getRandomKey();
            m.encrypt(key, iv, Mode.CBC);
        }
        return m.getData();
    }

    private static byte[] getRandomKey() {
        byte[] bytes = new byte[16];
        random.nextBytes(bytes);
        return bytes;
    }
}
