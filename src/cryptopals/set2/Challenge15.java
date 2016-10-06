/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cryptopals.set2;

/**
 *
 * @author balsfull
 */
public class Challenge15 {
    
//    public static void main(String[] args) {
//        String padded = Challenge9.pad("YELLOW SUBMARINE", 40);
//        System.out.println("Padded: " + padded);
//        System.out.println("Unpadded: " + unpad(padded));
//        
//    }
    
    public static String unpad(String padded) {
        byte[] bytes = padded.getBytes();
        byte last = bytes[bytes.length - 1];
        for(int i = 1; i <= last; i++) {
            if(bytes[bytes.length - i] != last) {
                throw new UnsupportedOperationException("String not padded!");
            }
        }
        return padded.substring(0, padded.length() - last);
    }
    
    public static byte[] unpad(byte[] bytes) {
        byte last = bytes[bytes.length - 1];
        for(int i = 1; i <= last; i++) {
            if(bytes[bytes.length - i] != last) {
                return bytes;
            }
        }
        byte[] unpadded = new byte[bytes.length - last];
        System.arraycopy(bytes, 0, unpadded, 0, unpadded.length);
        return unpadded;
    }
}
