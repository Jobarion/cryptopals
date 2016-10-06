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
public class Challenge2 {
    
    private final static String hex1 = "1c0111001f010100061a024b53535009181c";
    private final static String hex2 = "686974207468652062756c6c277320657965";
    
    //public static void main(String[] args) {
    //    System.out.println(xorHex(hex1, hex2));
    //}
    
    public static String xorHex(String hex1, String hex2) {
        StringBuilder xor = new StringBuilder();
        for(byte xorbyte : xor(hexStringToByteArray("1c0111001f010100061a024b53535009181c"), hexStringToByteArray("686974207468652062756c6c277320657965"))) {
            xor.append(Challenge1.decimalToHex((byte)(xorbyte >> 4)));
            xor.append(Challenge1.decimalToHex((byte)(xorbyte & 15)));
        }
        return xor.toString();
    }
    
    public static byte[] xor(byte[] arr1, byte[] arr2) {
        byte[] xor = new byte[Math.max(arr1.length, arr2.length)];
        for(int i = 0; i < arr1.length; i++) {
            xor[i] = (byte)(arr1[i] ^ arr2[i % arr2.length]); 
        }
        return xor;
    }
    
    public static byte[] hexStringToByteArray(String hex) {
        byte[] bytes = new byte[hex.length() / 2];
        for(int i = 0; i < hex.length(); i++) {
            if(i % 2 == 0) {
                bytes[i / 2] = (byte)(Challenge1.hexToDecimal(hex.charAt(i)) << 4);
            }
            else {
                bytes[i / 2] += Challenge1.hexToDecimal(hex.charAt(i));
            }
        }
        return bytes;
    }
    
    
    public static String byteArrayToHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for(int i = 0; i < bytes.length; i++) {
            sb.append(Challenge1.decimalToHex((byte)((bytes[i] >> 4) & 0xF)));
            sb.append(Challenge1.decimalToHex((byte)((bytes[i] & 15) & 0xF)));
        }
        return sb.toString();
    }
}
