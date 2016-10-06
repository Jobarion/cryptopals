/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cryptopals.set5;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

/**
 *
 * @author Jonas
 */
public class RSA {
    
    private static final Random random = new SecureRandom();
    private static final BigInteger e = BigInteger.valueOf(3);
    
    public static Tuple<Key, Key> generateKeypair(int length) {
        BigInteger et, n;
        do {
            BigInteger p = BigInteger.probablePrime(length, random);
            BigInteger q = BigInteger.probablePrime(length, random);
            n = p.multiply(q);
            et = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        } while(et.gcd(e).intValue() > 1);
        BigInteger d = e.modInverse(et);
        return new Tuple<>(new Key(e, n), new Key(d, n));
    }
    
    public static BigInteger encrypt(BigInteger m, Key key) {
        return m.modPow(key.key, key.modulus);
    }
    
    public static BigInteger decrypt(BigInteger c, Key key) {
        return encrypt(c, key);
    }
    
    public static class Key {
        
        public final BigInteger key, modulus;
        
        protected Key(BigInteger key, BigInteger modulus) {
            this.key = key;
            this.modulus = modulus;
        }
    }
}
