/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cryptopals.set5;

import cryptopals.set1.Challenge2;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;

/**
 *
 * @author balsfull
 */
public class Challenge36 {
    
    private static final Random random = new Random();
    private static BigInteger N = new BigInteger("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327fffffffffffffff", 16);
    private static BigInteger g = new BigInteger("2");
    private static BigInteger k = new BigInteger("3");
    
    private static String passwordString = "peter123";
    private static BigInteger P = new BigInteger(Challenge2.byteArrayToHexString(passwordString.getBytes()), 16);
    
//    public static void main(String[] args) {
//        EchoBotClient client = new EchoBotClient();
//        EchoBotServer server = new EchoBotServer();
//        server.step1();
//        Tuple<String, BigInteger> result1 = client.step1();
//        Tuple<BigInteger, BigInteger> result2 = server.step2(result1.k, result1.v);
//        byte[] hmac = client.step2(result2.k, result2.v);
//        System.out.println(server.step3(hmac));
//    }
    
    private static class EchoBotServer {
        
        private BigInteger A, B, salt, v, b;
        private String I;
        
        public EchoBotServer() {
            this.b= BigInteger.valueOf(random.nextInt(91) + 10);
        }
        
        public void step1() {
            salt = BigInteger.valueOf(random.nextInt());
            String xH = Challenge2.byteArrayToHexString(SHA256.hash(salt.or(P).toByteArray()));
            BigInteger x = new BigInteger(xH, 16);
            v = g.modPow(x, N);
        }
        
        public Tuple<BigInteger, BigInteger> step2(String I, BigInteger A) {
            this.I = I;
            this.A = A;
            B = g.modPow(b, N).add(k.multiply(v));
            return new Tuple<>(salt, B);
        }
        
        public boolean step3(byte[] hmac) {
            String uH = Challenge2.byteArrayToHexString(SHA256.hash(A.or(B).toByteArray()));
            BigInteger u = new BigInteger(uH, 16);
            BigInteger S = A.multiply(v.modPow(u, N)).modPow(b, N);
            System.out.println("Server: " + S);
            byte[] K = SHA256.hash(S.toByteArray());
            byte[] correctHMAC = HMAC.hmac_sha256(K, salt.toByteArray());
            if(correctHMAC.length != hmac.length) {
                return false;
            }
            for(int i = 0; i < correctHMAC.length; i++) {
                if(correctHMAC[i] != hmac[i]) {
                    return false;
                }
            }
            return true;
        }
    }
    
    private static class EchoBotClient {
        
        private BigInteger a, A, B;
        private final String I = "test@example.com";
        
        public EchoBotClient() {
            this.a = BigInteger.valueOf(random.nextInt(91) + 10);
            this.A = g.modPow(a, N);
            this.A = BigInteger.ZERO;//Zero key prep, turns S into 0 serverside, makes password unnecessary
        }
        
        public Tuple<String, BigInteger> step1() {
            return new Tuple<>(I, A);
        }
        
        public byte[] step2(BigInteger salt, BigInteger B) {
            this.B = B;
            String uH = Challenge2.byteArrayToHexString(SHA256.hash(A.or(B).toByteArray()));
            BigInteger u = new BigInteger(uH, 16);
            String xH = Challenge2.byteArrayToHexString(SHA256.hash(salt.or(P).toByteArray()));
            BigInteger x = new BigInteger(xH, 16);
            BigInteger S = B.subtract(k.multiply(g.modPow(x, N))).modPow(a.add(u.multiply(x)), N);
            S = BigInteger.ZERO;//Zero key
            System.out.println("Client: " + S);
            byte[] K = SHA256.hash(S.toByteArray());
            return HMAC.hmac_sha256(K, salt.toByteArray());
        }
    }
}
