/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cryptopals.set1;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import javax.xml.bind.DatatypeConverter;

/**
 *
 * @author balsfull
 */
public class Challenge6 {
    
//    public static void main(String[] args) {
//        String encrypted = new String(DatatypeConverter.parseBase64Binary(Challenge6.encrypted));//Challenge2.byteArrayToHexString(DatatypeConverter.parseBase64Binary(Challenge6.encrypted));
//        String key = new String(new char[]{'T', 101, 114, 109, 105, 110, 97, 116, 111, 114, 32, 88, 58, 32, 66, 114, 105, 110, 103, 32, 116, 104, 101, 32, 110, 111, 105, 115, 101});
//        System.out.println(decrypt(encrypted, key.length()));
//        String decrypted = new String(Challenge2.xor(encrypted.getBytes(), key.getBytes()));
//        System.out.println(decrypted);
//        System.out.println(getKeysizeGuess(encrypted, key.length() + 5));
//    }
       
    public static String decrypt(String encrypted, int keysize) {
        String[] transposed = transpose(splitToBlocks(encrypted, keysize));
        Map<Integer, Map<Character, String>> blockSolutions = new HashMap<>();
        for(int i = 0; i < keysize; i++) {
            System.out.println("Block " + i);
            blockSolutions.put(i, Challenge3.bruteForce(transposed[i]));
        }
        for(int i = 0; i < keysize; i++) {
            if(blockSolutions.get(i).isEmpty()) return "";
        }
        return "";
    }
    
    public static int getKeysizeGuess(String encrypted, int maxLength) {
        byte[] bytes = encrypted.getBytes();
        int min = -1;
        double minDistance = Double.POSITIVE_INFINITY;
        for(int keysize = 1; keysize < maxLength && 4 * keysize <= encrypted.length(); keysize++) {
            byte[] first = new byte[keysize], second = new byte[keysize];
            System.arraycopy(bytes, 0, first, 0, keysize);
            System.arraycopy(bytes, keysize, second, 0, keysize);
            double distanceNormalized = hammingDistance(first, second) / (double)keysize;
            System.arraycopy(bytes, keysize * 2, first, 0, keysize);
            System.arraycopy(bytes, keysize * 3, second, 0, keysize);
            distanceNormalized += hammingDistance(first, second) / (double)keysize;
            distanceNormalized /= 2;
            System.out.println(keysize + ": " + distanceNormalized);
            if(minDistance > distanceNormalized) {
                min = keysize;
                minDistance = distanceNormalized;
            }
        }
        return min;
    }
    
    public static String[] transpose(String[] array) {
        String[] transposed = new String[array[0].length()];
        Arrays.fill(transposed, "");
        for(String s : array) {
            for(int i = 0; i < s.length(); i++) {
                transposed[i] += s.charAt(i);
            }
        }
        return transposed;
    }
    
    public static String[] splitToBlocks(String s, int length) {
        String[] blocks = new String[(int)Math.ceil(s.length() / (double)length)];
        Arrays.fill(blocks, "");
        for(int i = 0; i < s.length(); i++) {
            blocks[i / length] += s.charAt(i);
        }
        return blocks;
    }
    
    public static int hammingDistance(String s1, String s2) {
        return hammingWeight(Challenge2.xor(s1.getBytes(), s2.getBytes()));
    }
    
    public static int hammingDistance(byte[] b1, byte[] b2) {
        return hammingWeight(Challenge2.xor(b1, b2));
    }
    
    public static int hammingWeight(byte[] bytes) {
        int weight = 0;
        for(byte i : bytes) {
            i = (byte)(i - ((i >>> 1) & 0x55555555));
            i = (byte)((i & 0x33333333) + ((i >> 2) & 0x33333333));
            weight += (((i + (i >> 4)) & 0x0F0F0F0F) * 0x01010101) >> 24;
        }
        return weight;
    } 
    
    private static final String encrypted = "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";
}
