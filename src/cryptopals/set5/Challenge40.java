/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cryptopals.set5;

import cryptopals.set5.RSA.Key;
import java.math.BigInteger;

/**
 *
 * @author Jonas
 */
public class Challenge40 {
    
//    public static void main(String[] args) {
//        int length = 1024;
//        Key key0 = RSA.generateKeypair(length).k;
//        Key key1 = RSA.generateKeypair(length).k;
//        Key key2 = RSA.generateKeypair(length).k;
//        String message = "Hello, you are a moron for encrypting it three times";
//        BigInteger bi = new BigInteger(message.getBytes());
//        BigInteger c0 = RSA.encrypt(bi, key0);
//        BigInteger c1 = RSA.encrypt(bi, key1);
//        BigInteger c2 = RSA.encrypt(bi, key2);
//        BigInteger ms0 = key1.modulus.multiply(key2.modulus);
//        BigInteger ms1 = key0.modulus.multiply(key2.modulus);
//        BigInteger ms2 = key0.modulus.multiply(key1.modulus);
//        BigInteger n012 = key0.modulus.multiply(key1.modulus).multiply(key2.modulus);
//        BigInteger result = (c0.multiply(ms0).multiply(ms0.modInverse(key0.modulus))
//                .add(c1.multiply(ms1).multiply(ms1.modInverse(key1.modulus)))
//                .add(c2.multiply(ms2).multiply(ms2.modInverse(key2.modulus)))).mod(n012);
//        BigInteger root = root(result, 3);
//        System.out.println(new String(root.toByteArray()));
//    }
    
    public static BigInteger root(BigInteger n, int l) {
        int c = 10000000;
        BigInteger low = BigInteger.ONE;
        BigInteger high = n;
        BigInteger guess = n.divide(BigInteger.valueOf(l));
        BigInteger lastguess = guess;
        BigInteger res = guess.pow(l);
        
        while(c > 0 && res.compareTo(n) != 0) {
            lastguess = guess;
            if(res.compareTo(n) < 0) {
                low = guess;
                guess = guess.add(high.subtract(guess).divide(BigInteger.valueOf(2)));
            }
            else {
                high = guess;
                guess = guess.subtract(guess.subtract(low).divide(BigInteger.valueOf(2)));
            }
            res = guess.pow(l);
            c--;
            if(guess.compareTo(lastguess) == 0) {
                return guess;
            }
        }
        return guess;
    }
}
