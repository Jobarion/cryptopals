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
public class Challenge1 {
    
    private static final String alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    public static String toBase64(String hex) {
        StringBuilder result = new StringBuilder();
        
        for(int i = 0; i < hex.length(); i += 3) {
            byte b1 = hexToDecimal(hex.charAt(i));
            byte b2 = hexToDecimal(hex.charAt(i + 1));
            byte b3 = hexToDecimal(hex.charAt(i + 2));
            result.append(alpha.charAt((b1 << 2) + (b2 >> 2)));
            result.append(alpha.charAt(((b2 & 3) << 4) + b3));
        }
        return result.toString();
    }
    
    public static byte hexToDecimal(char hex) {
        if('0' <= hex && hex <= '9') {
            return (byte)(hex - '0');
        }

        if(hex >= 'A' && hex <= 'Z') {
            return (byte)(hex - 'A' + 10);
        }

        return (byte)(hex - 'a' + 10);
    }
    
    public static char decimalToHex(byte decimal) {
        return (char)((decimal > 9) ? 'a' + decimal % 10 : '0' + decimal);
    }
}
