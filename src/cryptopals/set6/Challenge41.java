/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cryptopals.set6;

import cryptopals.set5.RSA;
import cryptopals.set5.RSA.Key;
import cryptopals.set5.Tuple;
import java.math.BigInteger;
import java.util.HashSet;

/**
 *
 * @author Jonas
 */
public class Challenge41 {
    
    public static void main(String[] args) {
        String secret = "My terrible secret";
        Tuple<Key, Key> keypair = RSA.generateKeypair(128);
        BigInteger c = RSA.encrypt(new BigInteger(secret.getBytes()), keypair.k);
        BigInteger s = BigInteger.valueOf(2);//Arbitrary, > 1
        BigInteger c_ = s.modPow(keypair.k.key, keypair.k.modulus).multiply(c).mod(keypair.k.modulus);
        BigInteger p_ = RSA.decrypt(c_, keypair.v);
        BigInteger p = p_.multiply(s.modInverse(keypair.k.modulus)).mod(keypair.k.modulus);
        System.out.println(new String(p.toByteArray()));
    }
}
