/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cryptopals.set5;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 *
 * @author balsfull
 */
public class SHA256 {
    
    public static byte[] hash(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(data);
            return md.digest();
        } catch (NoSuchAlgorithmException ex) {
            return null;
        }
    }
}
