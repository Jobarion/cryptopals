/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cryptopals.set2;

import java.util.Arrays;

/**
 *
 * @author balsfull
 */
public class Challenge9 {
    
//    public static void main(String[] args) {
//        System.out.println(pad("YELLOW SUBMARINE", 20));
//    }
    
    public static String pad(String s, int l) {
        if(s.length() >= l) {
            return s;
        }
        else {
            char[] pad = new char[l];
            char pval = (char)(l - s.length());
            Arrays.fill(pad, pval);
            System.arraycopy(s.toCharArray(), 0, pad, 0, s.length());
            return new String(pad);
        }
    }
    
    public static byte[] padMultiple(byte[] s, int l) {
        if(s.length % l == 0) {
            return s;
        }
        else {
            l = (int)(Math.ceil(s.length / (double)l) * l);
            byte[] pad = new byte[l];
            byte pval = (byte)(l - s.length);
            Arrays.fill(pad, pval);
            System.arraycopy(s, 0, pad, 0, s.length);
            return pad;
        }
    }
}
