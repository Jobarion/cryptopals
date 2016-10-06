/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cryptopals.set1;

/**
 *
 * @author balsfull
 */
public class Challenge5 {
    
    private static final String decrypted = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    
//    public static void main(String[] args) {
//        System.out.println(encryptXOR(decrypted, "ICE"));
//    }
    
    public static String encryptXOR(String message, String key) {
        byte[] bytes = message.getBytes();
        byte[] encrypted = Challenge2.xor(bytes, key.getBytes());
        return new String(encrypted);
    }
    
    public static String encryptXORToHex(String message, String key) {
        byte[] bytes = message.getBytes();
        byte[] encrypted = Challenge2.xor(bytes, key.getBytes());
        return Challenge2.byteArrayToHexString(encrypted);
    }
}
