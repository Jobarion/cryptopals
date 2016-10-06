package cryptopals;

import static cryptopals.set1.Challenge2.xor;
import cryptopals.set1.Challenge7.Message;
import cryptopals.set1.Challenge7.Message.Counter;
import cryptopals.set1.Challenge7.Mode;
import java.util.Random;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author balsfull
 */
public class Debug {
    
    public static boolean DEBUG = true;
    
//    public static void main(String[] args) {
//        Random random = new Random();
//        byte[] key = new byte[16];
//        byte[] n = new byte[8];
//        random.nextBytes(n);
//        random.nextBytes(key);
//        byte[] plain = "YELLOW SUBMARINE0123456789ABCDEF".getBytes();
//        Message message = new Message(new byte[32]);
//        message.encrypt(key, n, Counter.getDefault(8), Mode.CTR);
//        byte[] keystream = message.getData();
//        message = new Message(plain);
//        message.encrypt(key, n, Counter.getDefault(8), Mode.CTR);
//        byte[] encrypted = message.getData();
//        System.out.println(new String(xor(encrypted, keystream)));
//    }
}
