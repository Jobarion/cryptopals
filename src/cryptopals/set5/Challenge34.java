/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cryptopals.set5;

import cryptopals.set1.Challenge2;
import cryptopals.set1.Challenge7;
import cryptopals.set1.Challenge7.Message;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

/**
 *
 * @author balsfull
 */
public class Challenge34 {
    
    private static Random random = new SecureRandom();
    
//    public static void main(String[] args) {
//        BigInteger p = new BigInteger("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327fffffffffffffff", 16);
//        BigInteger g = new BigInteger("2");
//        String message = "Yellow Submarine";
//        EchoBot1 bot1 = new EchoBot1();
//        EchoBot2 bot2 = new EchoBot2();
//        BigInteger A = bot1.step1(p, g);
//        A = p;//Key fixing
//        BigInteger B = bot2.step1(p, g, A);
//        B = p;
//        Tuple<byte[], byte[]> result1 = bot1.step2(B);
//        Tuple<byte[], byte[]> result2 = bot2.step2(result1.k, result1.v);
//        //Normal s is (B^a mod p), (p^a mod p however is always zero)
//        BigInteger s = BigInteger.ZERO;
//        byte[] hash = SHA1.hash(s.toByteArray());
//        byte[] key = new byte[16];
//        System.arraycopy(hash, 0, key, 0, key.length);
//        Message m1 = new Message(result2.k);
//        m1.decrypt(key, result2.v, Challenge7.Mode.CBC);
//        byte[] decrypted = m1.getData();
//        System.out.println(new String(decrypted));
//    }
    
    private static class EchoBot1 {
        
        private BigInteger a, s, p, g;
        private static String message = "Yellow Submarine";
        
        public EchoBot1() {
            this.a= BigInteger.valueOf(random.nextInt(91) + 10);
        }
        
        public BigInteger step1(BigInteger p, BigInteger g) {
            this.p = p;
            this.g = g;
            return g.modPow(a, p);
        }
        
        public Tuple<byte[], byte[]> step2(BigInteger B) {
            s = B.modPow(a, p);
            byte[] hash = SHA1.hash(s.toByteArray());
            byte[] key = new byte[16];
            System.arraycopy(hash, 0, key, 0, key.length);
            byte[] iv = new byte[16];
            random.nextBytes(iv);
            Message m2 = new Message(message.getBytes());
            m2.encrypt(key, iv, Challenge7.Mode.CBC);
            return new Tuple<>(m2.getData(), iv);
        }
    }
    
    private static class EchoBot2 {
        
        private BigInteger b, s;
        
        public EchoBot2() {
            this.b= BigInteger.valueOf(random.nextInt(91) + 10);
        }
        
        public BigInteger step1(BigInteger p, BigInteger g, BigInteger A) {
            s = A.modPow(b, p);
            System.out.println(s);
            return g.modPow(b, p);
        }
        
        public Tuple<byte[], byte[]> step2(byte[] encrypted, byte[] iv) {
            byte[] hash = SHA1.hash(s.toByteArray());
            byte[] key = new byte[16];
            System.arraycopy(hash, 0, key, 0, key.length);
            Message m1 = new Message(encrypted);
            m1.decrypt(key, iv, Challenge7.Mode.CBC);
            byte[] decrypted = m1.getData();
            byte[] ownIV = new byte[16];
            random.nextBytes(ownIV);
            Message m2 = new Message(decrypted);
            m2.encrypt(key, ownIV, Challenge7.Mode.CBC);
            return new Tuple<>(m2.getData(), ownIV);
        }
    }
}