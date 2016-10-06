/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cryptopals.set5;

import java.util.Arrays;

/**
 *
 * @author balsfull
 */
public class SHA1 {
    
    private static byte[] expand(byte[] message, int length) {
        int missing = (512 - ((length + 1) % 512)) % 512;
        int blocks = (length + missing + 1) / 8;
        if(message.length != blocks) {
            byte[] nMessage = new byte[blocks];
            System.arraycopy(message, 0, nMessage, 0, message.length);
            message = nMessage;
        }
        message[length / 8] |= (0x80) >> (length % 8);
        long lengthl = length;
        message[message.length - 8] = (byte) ((lengthl & 0xFF) >> 56);
        message[message.length - 7] = (byte) ((lengthl & 0x00FF) >> 48);
        message[message.length - 6] = (byte) ((lengthl & 0x0000FF) >> 40);
        message[message.length - 5] = (byte) ((lengthl & 0x000000FF) >> 32);
        message[message.length - 4] = (byte) ((lengthl & 0x00000000FF) >> 24);
        message[message.length - 3] = (byte) ((lengthl & 0x0000000000FF) >> 16);
        message[message.length - 2] = (byte) ((lengthl & 0x000000000000FF) >> 8);
        message[message.length - 1] = (byte) ((lengthl & 0x00000000000000FF) >> 0);
        return message;
    }
    
    public static byte[] hash(byte[] message) {
        return hash(message, message.length * 8);
    }
    
    public static byte[] hash(byte[] message, int length) {
        int h0 = 0x67452301;
        int h1 = 0xEFCDAB89;
        int h2 = 0x98BADCFE;
        int h3 = 0x10325476;
        int h4 = 0xC3D2E1F0;
        message = expand(message, length);
        for(int bid = 0; bid < message.length / 64; bid++) {
            int[] w = new int[80];
            int offset = bid * 64;
            for(int i = 0; i < 16; i++) {
                w[i] = message[offset++] << 24 | (message[offset++] & 0xFF) << 16 | (message[offset++] & 0xFF) << 8 | (message[offset++] & 0xFF);
            }
            for(int i = 16; i < w.length; i++) {
                w[i] = Integer.rotateLeft(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
            }
            int a = h0;
            int b = h1;
            int c = h2;
            int d = h3;
            int e = h4;
            for(int i = 0; i < 80; i++) {
                int f, k;
                if(i <= 19) {
                    f = (b & c) | ((~b) & d);
                    k = 0x5A827999;
                }
                else if(i <= 39) {
                    f = b ^ c ^ d;
                    k = 0x6ED9EBA1;
                }
                else if(i <= 59) {
                    f = (b & c) | (b & d) | (c & d);
                    k = 0x8F1BBCDC;
                }
                else {
                    f = b ^ c ^ d;
                    k = 0xCA62C1D6;
                }
                int temp = Integer.rotateLeft(a, 5) + f + e + k + w[i];
                e = d;
                d = c;
                c = Integer.rotateLeft(b, 30);
                b = a;
                a = temp;
            }
            h0 = h0 + a;
            h1 = h1 + b;
            h2 = h2 + c;
            h3 = h3 + d;
            h4 = h4 + e;
            
        }
        byte[] digest = new byte[20];
        copy(digest, h0, 0);
        copy(digest, h1, 4);
        copy(digest, h2, 8);
        copy(digest, h3, 12);
        copy(digest, h4, 16);
        return digest;
    }
    
    private static void copy(byte[] array, int value, int offset) {
        array[offset + 0] = (byte) ((value & 0xFF000000) >> 24);
        array[offset + 1] = (byte) ((value & 0x00FF0000) >> 16);
        array[offset + 2] = (byte) ((value & 0x0000FF00) >> 8);
        array[offset + 3] = (byte) ((value & 0x000000FF) >> 0);
    }   
}