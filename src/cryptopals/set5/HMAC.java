/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cryptopals.set5;

import cryptopals.set1.Challenge2;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.function.Function;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author balsfull
 */
public class HMAC {
    
//    public static byte[] hmac_sha256(byte[] key, byte[] data) {
//        int blocksize = 64;
//        if(key.length > blocksize) {
//            key = hashFunction.apply(key);
//        }
//        if(key.length < blocksize) {
//            byte[] newkey = new byte[blocksize];
//            System.arraycopy(key, 0, newkey, 0, key.length);
//            key = newkey;
//        }
//        System.out.println(Arrays.toString(key));
//        byte[] i_key_pad = new byte[blocksize];
//        byte[] o_key_pad = new byte[blocksize];
//        Arrays.fill(i_key_pad, (byte)0x36);
//        Arrays.fill(o_key_pad, (byte)0x5C);
//        i_key_pad = Challenge2.xor(key, i_key_pad);
//        byte[] unhashed = new byte[blocksize + data.length];
//        System.out.println(unhashed.length);
//        System.arraycopy(i_key_pad, 0, unhashed, 0, i_key_pad.length);
//        System.arraycopy(data, 0, unhashed, blocksize, data.length);
//        System.out.println(new String(unhashed));
//        byte[] hashedInner = hashFunction.apply(i_key_pad);
//        System.out.println(Challenge2.byteArrayToHexString(hashedInner));
//        o_key_pad = Challenge2.xor(key, o_key_pad);
//        unhashed = new byte[o_key_pad.length + hashedInner.length];
//        System.arraycopy(o_key_pad, 0, unhashed, 0, o_key_pad.length);
//        System.arraycopy(hashedInner, 0, unhashed, blocksize, hashedInner.length);
//        return hashFunction.apply(unhashed);
//    }
    public static byte[] hmac_sha256(byte[] msg, byte[] key) {
        return hmacDigest(msg, key, "HMACSha256");
    }

    private static byte[] hmacDigest(byte[] msg, byte[] keyBytes, String algo) {
        try {
            SecretKeySpec key = new SecretKeySpec(keyBytes, algo);
            Mac mac = Mac.getInstance(algo);
            mac.init(key);
            byte[] bytes = mac.doFinal(msg);
            return bytes;
        } catch (InvalidKeyException | NoSuchAlgorithmException ex) {
            Logger.getLogger(HMAC.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
}
