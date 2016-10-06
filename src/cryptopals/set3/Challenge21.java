/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cryptopals.set3;

import java.util.ArrayList;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author balsfull
 */
public class Challenge21 {
 
//    public static void main(String[] args) {
//        int first = getFirst();
//        System.out.println(first);
//        long seed = crackMersenne(first);
//        System.out.println(seed);
//        Random rand = new Random(seed);
//        int[] s = new int[Mersenne.N];
//        for(int i = 0; i < s.length; i++) {
//            s[i] = rand.nextInt();
//        }
//        Mersenne m = new Mersenne(s);  
//        System.out.println(m.next());
//    }
    
    public static long crackMersenne(int first) {
        long time = System.currentTimeMillis() / 1000 + 1;
        int result = -1;
        Random rand;
        while(result != first) {
            time--;
            rand = new Random(time);
            int[] seed = new int[Mersenne.N];
            for(int i = 0; i < seed.length; i++) {
                seed[i] = rand.nextInt();
            }
            Mersenne m = new Mersenne(seed);
            result = m.next();
        }
        return time;
    }
    
    public static int getFirst() {
        try {
            Random rand = new Random();
            Thread.sleep(rand.nextInt(100) * 1000);
            rand = new Random(System.currentTimeMillis() / 1000);
            int[] seed = new int[Mersenne.N];
            for(int i = 0; i < seed.length; i++) {
                seed[i] = rand.nextInt();
            }
            Mersenne m = new Mersenne(seed);
            Thread.sleep(rand.nextInt(100) * 1000);
            return m.next();
        } catch(InterruptedException ex) {
            Logger.getLogger(Challenge21.class.getName()).log(Level.SEVERE, null, ex);
        }
        return -1;
        
    }
    
    public static class Mersenne {
        
        private static final int N = 624;
        private static final int M = 397;
        private static final int MATRIX_A = 0x9908b0df;   //    private static final * constant vector a
        private static final int UPPER_MASK = 0x80000000; // most significant w-r bits
        private static final int LOWER_MASK = 0x7fffffff; // least significant r bits
        private static final int TEMPERING_MASK_B = 0x9d2c5680;
        private static final int TEMPERING_MASK_C = 0xefc60000;
        private int mag01[] = new int[]{0, MATRIX_A};
        private int index = 0;
        private int[] y;
        
        public Mersenne(int[] seed) {
            y = seed;
            
        }
        
        public int next() {
            int yi;
            
            if(index >= N) {
                int kk;
                for(kk = 0; kk < N - M; kk++) {
                    yi = (y[kk] & UPPER_MASK) | (y[kk + 1] & LOWER_MASK);
                    y[kk] = y[kk + M] ^ (yi >>> 1) ^ mag01[yi & 0x1];
                }
                for(;kk < N - 1; kk++) {
                    yi = (y[kk] & UPPER_MASK) | (y[kk + 1] & LOWER_MASK);
                    y[kk] = y[kk + (M - N)] ^ (yi >>> 1) ^ mag01[yi & 0x1];
                }
                yi = (y[N - 1] & UPPER_MASK) | (y[0] & LOWER_MASK);
                y[N - 1] = y[M - 1] ^ (yi >>> 1) ^ mag01[yi & 0x1];
                index = 0;
            }
            yi = y[index++];
            yi ^= yi >>> 11;
            yi ^= (yi << 7) & 0x9d2c5680;
            yi ^= (yi << 15) & 0xefc60000;
            yi ^= (yi >>> 18);
            return yi;
        }
    }
}
