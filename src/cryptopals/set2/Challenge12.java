/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cryptopals.set2;

import cryptopals.set1.Challenge7.Message;
import cryptopals.set1.Challenge7.Mode;
import static cryptopals.set1.Challenge7.copy;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import javax.xml.bind.DatatypeConverter;

/**
 *
 * @author balsfull
 */
public class Challenge12 {

    private static final Random random = new Random(12345678);
    private static final byte[] ckey = new byte[16];

//    public static void main(String[] args) {
//        crackECB();
//    }

    public static byte[] crackECB() {
        Mode mode = Challenge11.getMode(encrypt(new byte[0]));
        if(mode != Mode.ECB) {
            throw new UnsupportedOperationException("Algorithm can only crack ECB encrypted arrays.");
        }
        else {
            int blocksize = getBlocksize();
            System.out.println("Blocksize: " + blocksize);
            ArrayList<Byte> resultArray = new ArrayList<>();
            boolean breakLoop = false;
            for(int block = 0; !breakLoop; block++) {
                for(int j = 0; j < blocksize; j++) {
                    byte[] shortResult = encrypt(new byte[blocksize - (resultArray.size() % blocksize) - 1], block);
                    if(shortResult == null) {
                        breakLoop = true;
                        break;
                    }
                    else {
                        byte[] knownDataArray = getLastBytes(resultArray, (block + 1) * blocksize - 1);
                        for(byte[] testData : generateRandomArrays(append(knownDataArray, new byte[1]), knownDataArray.length)) {
                            byte[] encryptedTest = encrypt(testData, block);
                            if(equals(shortResult, encryptedTest)) {
                                resultArray.add(testData[testData.length - 1]);
                                break;
                            }
                        }
                    }
                }
            }
            System.out.println(new String(getLastBytes(resultArray, resultArray.size())));
        }
        return null;
    }

    public static boolean equals(byte[] b1, byte[] b2) {
        if(b1.length == b2.length) {
            for(int i = 0; i < b1.length; i++) {
                if(b1[i] != b2[i]) {
                    return false;
                }
            }
            return true;
        }
        return false;
    }

    private static byte[] getLastBytes(List<Byte> in, int amount) {
        byte ret[] = new byte[amount];
        for(int i = 1; i <= amount && i <= in.size(); i++) {
            ret[amount - i] = in.get(in.size() - i);
        }
        return ret;
    }

    private static byte[] encrypt(byte[] m) {
        Message message = new Message(append(m, toCrack));
        message.encrypt(ckey, Mode.ECB);
        return message.getData();
    }

    private static byte[] encrypt(byte[] m, int block) {
        Message message = new Message(append(m, toCrack));
        message.encrypt(ckey, Mode.ECB);
        return message.getData(block);
    }

    private static byte[][] generateRandomArrays(byte[] bytes, int randomIndex) {
        byte[][] all = new byte[256][bytes.length];
        for(int i = 0; i < all.length; i++) {
            all[i] = copy(bytes);
        }
        for(int b = Byte.MIN_VALUE; b <= Byte.MAX_VALUE; b++) {
            all[b - Byte.MIN_VALUE][randomIndex] = (byte)b;
        }
        return all;
    }

    public static int getBlocksize() {
        int blockSize = 0;
        for(int i = 1; i < 20; i++) {
            int currSize = encrypt(new byte[i]).length;
            if(blockSize == 0) {
                blockSize = currSize;
            }
            else if(currSize > blockSize) {
                blockSize = currSize - blockSize;
                break;
            }
        }
        return blockSize;
    }

    public static byte[] append(byte[] b1, byte[] b2) {
        byte[] data = new byte[b1.length + b2.length];
        System.arraycopy(b1, 0, data, 0, b1.length);
        System.arraycopy(b2, 0, data, b1.length, b2.length);
        return data;

    }

    private static final byte[] toCrack = DatatypeConverter.parseBase64Binary(
            "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\n"
            + "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\n"
            + "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\n"
            + "YnkK");

    static {
        random.nextBytes(ckey);
    }
}
