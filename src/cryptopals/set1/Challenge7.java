/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cryptopals.set1;

import cryptopals.Debug;
import static cryptopals.set1.Challenge2.byteArrayToHexString;
import static cryptopals.set1.Challenge2.hexStringToByteArray;
import static cryptopals.set1.Challenge7.Message.transpose;
import static cryptopals.set2.Challenge12.append;
import java.util.Arrays;
import javax.xml.bind.DatatypeConverter;

/**
 *
 * @author balsfull
 */
public class Challenge7 {

    private static final int ksize = 128;
    private static final int rounds = 10;

//    public static void main(String[] args) throws Exception{
//        byte[] message = DatatypeConverter.parseBase64Binary(Challenge7.encoded);
//        byte[] key = "YELLOW SUBMARINE".getBytes();
//        Message m = new Message(message);
//        m.decrypt(key, Mode.ECB);
//        System.out.println(new String(m.getData()));
//    }
    public static void print(byte[] arr) {
        for(int i = 0; i < 16; i++) {
            if(i % 4 == 0 && i != 0) {
                System.out.println();
            }
            System.out.print(Integer.toHexString(arr[i] & 0xFF) + " ");
        }
        System.out.println();
    }

    public static byte[][] expandKey(byte[] key, byte[] sbox) {
        byte[][] expanded = new byte[rounds + 1][ksize / 8];
        expanded[0] = key;
        byte[] lastKey = copy(key);
        for(int i = 1; i <= 10; i++) {
            for(int wordID = 0; wordID < 4; wordID++) {
                if(wordID == 0) {
                    byte[] word = getWord(lastKey, 3);
                    rotWord(word);
                    subBytes(word, sbox);
                    xor(word, getWord(lastKey, 0));
                    xor(word, rcon[i - 1]);
                    setWord(lastKey, word, 0);
                }
                else {
                    byte[] word = getWord(lastKey, wordID);
                    xor(word, getWord(lastKey, wordID - 1));
                    setWord(lastKey, word, wordID);
                }
            }
            expanded[i] = copy(lastKey);
        }
        return expanded;
    }

    public static void xor(byte[] arr1, byte[] arr2) {
        for(int i = 0; i < arr1.length; i++) {
            arr1[i] ^= arr2[i];
        }
    }

    public static byte[] getWord(byte[] block, int wordID) {
        byte[] word = new byte[block.length / 4];
        for(int i = wordID; i < block.length; i += 4) {
            byte b = block[i];
            word[i / 4] = b;
        }
        return word;
    }

    public static void setWord(byte[] block, byte[] word, int wordID) {
        for(int i = 0; i < word.length; i++) {
            byte b = word[i];
            block[4 * i + wordID] = b;
        }
    }

    public static byte[] copy(byte[] bytes) {
        byte[] copy = new byte[bytes.length];
        System.arraycopy(bytes, 0, copy, 0, bytes.length);
        return copy;
    }

    private static void rotWord(byte[] word) {
        byte temp = word[0];
        word[0] = word[1];
        word[1] = word[2];
        word[2] = word[3];
        word[3] = temp;
    }

    private static void subBytes(byte[] word, byte[] sbox) {
        for(int i = 0; i < word.length; i++) {
            byte b = word[i];
            word[i] = (byte)sbox[(((b >> 4) * 0x10) + (b & 0xf)) & 0xFF];
        }
    }

    public static enum Mode {

        ECB,
        CBC,
        CTR;
    }

    public static class Message {

        private final Block[] blocks;

        public Message(byte[] bytes) {
            blocks = new Block[(int)Math.ceil(bytes.length / 16.0)];
            for(int i = 0; i < blocks.length; i++) {
                byte[] data = new byte[16];
                Arrays.fill(data, (byte)0);
                for(int j = 0; j < 16 && i * 16 + j < bytes.length; j++) {
                    data[j] = bytes[i * 16 + j];
                }
                blocks[i] = new Block(transpose(data));
            }
        }

        public static byte[] transpose(byte[] c) {
            byte[] t = new byte[c.length];
            int cid = 0;
            for(int i = 0; i != 16; i = (i > 0xB) ? i != 15 ? (i + 12) % 23 : 16 : i + 4) {
                t[i] = c[cid++];
            }
            return t;
        }

        public void encrypt(byte[] key, Mode mode) {
            encrypt(key, null, mode);
        }

        public void decrypt(byte[] key, Mode mode) {
            decrypt(key, null, mode);
        }

        public void encrypt(byte[] key, byte[] iv, Mode mode) {
            encrypt(key, iv, (mode == Mode.CTR) ? Counter.getDefault(16 - iv.length) : null, mode);
        }

        public void encrypt(byte[] key, byte[] iv, Counter counter, Mode mode) {
            byte[][] expanded = expandKey(transpose(key), s);
            switch(mode) {
                case ECB: {
                    for(Block block : blocks) {
                        block.encrypt(expanded);
                    }
                    break;
                }
                case CBC: {
                    for(Block block : blocks) {
                        block.xorData(iv);
                        block.encrypt(expanded);
                        iv = transpose(block.getData());
                    }
                    break;
                }
                case CTR: {
                    for(Block block : blocks) {
                        Message keystream = new Message(append(iv, counter.getValue()));
                        keystream.encrypt(key, Mode.ECB);
                        block.xorData(keystream.getData());
                        counter.increment();
                    }
                    break;
                }
            }
        }

        public void decrypt(byte[] key, byte[] iv, Mode mode) {
            if(mode == Mode.CTR) {
                encrypt(key, iv, mode);
            }
            else {
                decrypt(key, iv, null, mode);
            }
        }

        public void decrypt(byte[] key, byte[] iv, Counter counter, Mode mode) {
            if(mode == Mode.CTR) {
                encrypt(key, iv, counter, mode);
            }
            else {
                byte[][] expanded = expandKey(transpose(key), s);
                byte[] temp = iv;
                for(Block block : blocks) {
                    if(mode == Mode.ECB) {
                        block.decrypt(expanded);
                    }
                    else if(mode == Mode.CBC) {
                        byte[] transposedData = transpose(block.getData());
                        iv = copy(transposedData);
                        block.decrypt(expanded);
                        block.xorData(temp);
                        temp = iv;
                    }
                }
            }
        }

        public byte[] getData() {
            byte[] bytes = new byte[blocks.length * 16];
            for(int i = 0; i < blocks.length; i++) {
                Block block = blocks[i];
                System.arraycopy(transpose(block.getData()), 0, bytes, i * 16, 16);
            }
            return bytes;
        }

        public byte[] getData(int i) {
            return i < blocks.length ? transpose(blocks[i].getData()) : null;
        }

        public abstract static class Counter {

            private final byte[] value;

            public Counter(int length) {
                this.value = new byte[length];
            }

            public abstract void increment();

            public byte[] getValue() {
                return value;
            }

            public static Counter getDefault(int length) {
                return new Counter(length) {
                    @Override
                    public void increment() {
                        Challenge7.increment(this.getValue());
                    }
                };
            }
        }
    }

    public static class Block {

        private final byte[] block;

        public Block(byte[] block) {
            this.block = block;
        }

        public byte[] getData() {
            return block;
        }

        public void xorData(byte[] xor) {
            xor(block, transpose(xor));
        }

        private void encrypt(byte[][] expanded) {
            xor(block, expanded[0]);
            for(int i = 1; i < expanded.length; i++) {
                subBytes(block, s);
                shiftRows(block);
                if(i < expanded.length - 1) {
                    mixColumns(mix);
                }
                xor(block, expanded[i]);
            }
        }

        private void decrypt(byte[][] expanded) {
            xor(block, expanded[expanded.length - 1]);
            shiftRowsBack(block);
            subBytes(block, inv_s);
            for(int i = 9; i >= 0; i--) {
                xor(block, expanded[i]);
                if(i > 0) {
                    mixColumns(inv_mix);
                    shiftRowsBack(block);
                    subBytes(block, inv_s);
                }
            }
        }

        private void mixColumns(byte[][] mix) {
            for(int i = 0; i < block.length / 4; i++) {
                byte[] word = getWord(block, i);
                byte[] mixed = copy(word);
                for(int j = 0; j < word.length; j++) {
                    mixed[j] = (byte)((m(word[0], mix[j][0]) ^ m(word[1], mix[j][1]) ^ m(word[2], mix[j][2]) ^ m(word[3], mix[j][3])) % 0xFF);
                }
                setWord(block, mixed, i);
            }
        }

        private byte m(int c, int m) {
            c &= 0xFF;
            switch(m) {
                case 0x01: {
                    return (byte)c;
                }
                case 0x02: {
                    int r = (c << 1);
                    if(c >= 0x80) {
                        r ^= 0x1b;
                    }
                    return (byte)(r % 0x100);
                }
                case 0x03: {
                    return (byte)(m(c, (byte)2) ^ c);
                }
                case 0x09: {
                    return (byte)(m(m(m(c, 2), 2), 2) ^ c);
                }
                case 0x0B: {
                    return (byte)(m(m(m(c, 2), 2) ^ c, 2) ^ c);
                }
                case 0x0D: {
                    return (byte)(m(m(m(c, 2) ^ c, 2), 2) ^ c);
                }
                case 0x0E: {
                    return (byte)m(m(m(c, 2) ^ c, 2) ^ c, 2);
                }
                default: {
                    throw new RuntimeException("Multiplication error");
                }
            }
        }

        private void shiftRows(byte[] block) {
            byte temp = block[4];
            block[4] = block[5];
            block[5] = block[6];
            block[6] = block[7];
            block[7] = temp;
            block[8] = (byte)(block[8] ^ block[10]);
            block[10] = (byte)(block[8] ^ block[10]);
            block[8] = (byte)(block[8] ^ block[10]);
            block[9] = (byte)(block[9] ^ block[11]);
            block[11] = (byte)(block[9] ^ block[11]);
            block[9] = (byte)(block[9] ^ block[11]);
            temp = block[15];
            block[15] = block[14];
            block[14] = block[13];
            block[13] = block[12];
            block[12] = temp;
        }

        private void shiftRowsBack(byte[] block) {
            byte temp = block[7];
            block[7] = block[6];
            block[6] = block[5];
            block[5] = block[4];
            block[4] = temp;
            block[11] = (byte)(block[11] ^ block[9]);
            block[9] = (byte)(block[11] ^ block[9]);
            block[11] = (byte)(block[11] ^ block[9]);
            block[10] = (byte)(block[10] ^ block[8]);
            block[8] = (byte)(block[10] ^ block[8]);
            block[10] = (byte)(block[10] ^ block[8]);
            temp = block[12];
            block[12] = block[13];
            block[13] = block[14];
            block[14] = block[15];
            block[15] = temp;
        }
    }

    public static byte[] increment(byte[] array) {
        boolean carry = true;
        for(int i = (array.length - 1); i >= 0; i--) {
            if(carry) {
                if(array[i] == Byte.MAX_VALUE) {
                    array[i] = 0;
                    carry = true;
                }
                else {
                    array[i]++;
                    carry = false;
                }
            }
        }
        return array;
    }

    public static void flip(byte[] array) {
        for(int i = 0; i < array.length / 2; i++) {
            byte temp = array[i];
            array[i] = array[array.length - i - 1];
            array[array.length - i - 1] = temp;
        }
    }

    //AES-128 key: 128
    private static final byte[][] rcon = new byte[][]{
        {0x01, 0, 0, 0}, {0x02, 0x00, 0x00, 0x00}, {0x04, 0x00, 0x00, 0x00}, {0x08, 0x00, 0x00, 0x00}, {0x10, 0x00, 0x00, 0x00}, {0x20, 0x00, 0x00, 0x00}, {0x40, 0x00, 0x00, 0x00}, {(byte)0x80, 0x00, 0x00, 0x00}, {(byte)0x1b, 0x00, 0x00, 0x00}, {(byte)0x36, 0x00, 0x00, 0x00}
    };

    private static final byte[][] mix = new byte[][]{
        {0x02, 0x03, 0x01, 0x01},
        {0x01, 0x02, 0x03, 0x01},
        {0x01, 0x01, 0x02, 0x03},
        {0x03, 0x01, 0x01, 0x02}
    };

    private static final byte[][] inv_mix = new byte[][]{
        {0x0E, 0x0B, 0x0D, 0x09},
        {0x09, 0x0E, 0x0B, 0x0D},
        {0x0D, 0x09, 0x0E, 0x0B},
        {0x0B, 0x0D, 0x09, 0x0E}
    };

    private static final byte[] s = new byte[]{
        (byte)0x63, (byte)0x7C, (byte)0x77, (byte)0x7B, (byte)0xF2, (byte)0x6B, (byte)0x6F, (byte)0xC5, (byte)0x30, (byte)0x01, (byte)0x67, (byte)0x2B, (byte)0xFE, (byte)0xD7, (byte)0xAB, (byte)0x76,
        (byte)0xCA, (byte)0x82, (byte)0xC9, (byte)0x7D, (byte)0xFA, (byte)0x59, (byte)0x47, (byte)0xF0, (byte)0xAD, (byte)0xD4, (byte)0xA2, (byte)0xAF, (byte)0x9C, (byte)0xA4, (byte)0x72, (byte)0xC0,
        (byte)0xB7, (byte)0xFD, (byte)0x93, (byte)0x26, (byte)0x36, (byte)0x3F, (byte)0xF7, (byte)0xCC, (byte)0x34, (byte)0xA5, (byte)0xE5, (byte)0xF1, (byte)0x71, (byte)0xD8, (byte)0x31, (byte)0x15,
        (byte)0x04, (byte)0xC7, (byte)0x23, (byte)0xC3, (byte)0x18, (byte)0x96, (byte)0x05, (byte)0x9A, (byte)0x07, (byte)0x12, (byte)0x80, (byte)0xE2, (byte)0xEB, (byte)0x27, (byte)0xB2, (byte)0x75,
        (byte)0x09, (byte)0x83, (byte)0x2C, (byte)0x1A, (byte)0x1B, (byte)0x6E, (byte)0x5A, (byte)0xA0, (byte)0x52, (byte)0x3B, (byte)0xD6, (byte)0xB3, (byte)0x29, (byte)0xE3, (byte)0x2F, (byte)0x84,
        (byte)0x53, (byte)0xD1, (byte)0x00, (byte)0xED, (byte)0x20, (byte)0xFC, (byte)0xB1, (byte)0x5B, (byte)0x6A, (byte)0xCB, (byte)0xBE, (byte)0x39, (byte)0x4A, (byte)0x4C, (byte)0x58, (byte)0xCF,
        (byte)0xD0, (byte)0xEF, (byte)0xAA, (byte)0xFB, (byte)0x43, (byte)0x4D, (byte)0x33, (byte)0x85, (byte)0x45, (byte)0xF9, (byte)0x02, (byte)0x7F, (byte)0x50, (byte)0x3C, (byte)0x9F, (byte)0xA8,
        (byte)0x51, (byte)0xA3, (byte)0x40, (byte)0x8F, (byte)0x92, (byte)0x9D, (byte)0x38, (byte)0xF5, (byte)0xBC, (byte)0xB6, (byte)0xDA, (byte)0x21, (byte)0x10, (byte)0xFF, (byte)0xF3, (byte)0xD2,
        (byte)0xCD, (byte)0x0C, (byte)0x13, (byte)0xEC, (byte)0x5F, (byte)0x97, (byte)0x44, (byte)0x17, (byte)0xC4, (byte)0xA7, (byte)0x7E, (byte)0x3D, (byte)0x64, (byte)0x5D, (byte)0x19, (byte)0x73,
        (byte)0x60, (byte)0x81, (byte)0x4F, (byte)0xDC, (byte)0x22, (byte)0x2A, (byte)0x90, (byte)0x88, (byte)0x46, (byte)0xEE, (byte)0xB8, (byte)0x14, (byte)0xDE, (byte)0x5E, (byte)0x0B, (byte)0xDB,
        (byte)0xE0, (byte)0x32, (byte)0x3A, (byte)0x0A, (byte)0x49, (byte)0x06, (byte)0x24, (byte)0x5C, (byte)0xC2, (byte)0xD3, (byte)0xAC, (byte)0x62, (byte)0x91, (byte)0x95, (byte)0xE4, (byte)0x79,
        (byte)0xE7, (byte)0xC8, (byte)0x37, (byte)0x6D, (byte)0x8D, (byte)0xD5, (byte)0x4E, (byte)0xA9, (byte)0x6C, (byte)0x56, (byte)0xF4, (byte)0xEA, (byte)0x65, (byte)0x7A, (byte)0xAE, (byte)0x08,
        (byte)0xBA, (byte)0x78, (byte)0x25, (byte)0x2E, (byte)0x1C, (byte)0xA6, (byte)0xB4, (byte)0xC6, (byte)0xE8, (byte)0xDD, (byte)0x74, (byte)0x1F, (byte)0x4B, (byte)0xBD, (byte)0x8B, (byte)0x8A,
        (byte)0x70, (byte)0x3E, (byte)0xB5, (byte)0x66, (byte)0x48, (byte)0x03, (byte)0xF6, (byte)0x0E, (byte)0x61, (byte)0x35, (byte)0x57, (byte)0xB9, (byte)0x86, (byte)0xC1, (byte)0x1D, (byte)0x9E,
        (byte)0xE1, (byte)0xF8, (byte)0x98, (byte)0x11, (byte)0x69, (byte)0xD9, (byte)0x8E, (byte)0x94, (byte)0x9B, (byte)0x1E, (byte)0x87, (byte)0xE9, (byte)0xCE, (byte)0x55, (byte)0x28, (byte)0xDF,
        (byte)0x8C, (byte)0xA1, (byte)0x89, (byte)0x0D, (byte)0xBF, (byte)0xE6, (byte)0x42, (byte)0x68, (byte)0x41, (byte)0x99, (byte)0x2D, (byte)0x0F, (byte)0xB0, (byte)0x54, (byte)0xBB, (byte)0x16
    };

    private static final byte[] inv_s = new byte[]{
        (byte)0x52, (byte)0x09, (byte)0x6A, (byte)0xD5, (byte)0x30, (byte)0x36, (byte)0xA5, (byte)0x38, (byte)0xBF, (byte)0x40, (byte)0xA3, (byte)0x9E, (byte)0x81, (byte)0xF3, (byte)0xD7, (byte)0xFB,
        (byte)0x7C, (byte)0xE3, (byte)0x39, (byte)0x82, (byte)0x9B, (byte)0x2F, (byte)0xFF, (byte)0x87, (byte)0x34, (byte)0x8E, (byte)0x43, (byte)0x44, (byte)0xC4, (byte)0xDE, (byte)0xE9, (byte)0xCB,
        (byte)0x54, (byte)0x7B, (byte)0x94, (byte)0x32, (byte)0xA6, (byte)0xC2, (byte)0x23, (byte)0x3D, (byte)0xEE, (byte)0x4C, (byte)0x95, (byte)0x0B, (byte)0x42, (byte)0xFA, (byte)0xC3, (byte)0x4E,
        (byte)0x08, (byte)0x2E, (byte)0xA1, (byte)0x66, (byte)0x28, (byte)0xD9, (byte)0x24, (byte)0xB2, (byte)0x76, (byte)0x5B, (byte)0xA2, (byte)0x49, (byte)0x6D, (byte)0x8B, (byte)0xD1, (byte)0x25,
        (byte)0x72, (byte)0xF8, (byte)0xF6, (byte)0x64, (byte)0x86, (byte)0x68, (byte)0x98, (byte)0x16, (byte)0xD4, (byte)0xA4, (byte)0x5C, (byte)0xCC, (byte)0x5D, (byte)0x65, (byte)0xB6, (byte)0x92,
        (byte)0x6C, (byte)0x70, (byte)0x48, (byte)0x50, (byte)0xFD, (byte)0xED, (byte)0xB9, (byte)0xDA, (byte)0x5E, (byte)0x15, (byte)0x46, (byte)0x57, (byte)0xA7, (byte)0x8D, (byte)0x9D, (byte)0x84,
        (byte)0x90, (byte)0xD8, (byte)0xAB, (byte)0x00, (byte)0x8C, (byte)0xBC, (byte)0xD3, (byte)0x0A, (byte)0xF7, (byte)0xE4, (byte)0x58, (byte)0x05, (byte)0xB8, (byte)0xB3, (byte)0x45, (byte)0x06,
        (byte)0xD0, (byte)0x2C, (byte)0x1E, (byte)0x8F, (byte)0xCA, (byte)0x3F, (byte)0x0F, (byte)0x02, (byte)0xC1, (byte)0xAF, (byte)0xBD, (byte)0x03, (byte)0x01, (byte)0x13, (byte)0x8A, (byte)0x6B,
        (byte)0x3A, (byte)0x91, (byte)0x11, (byte)0x41, (byte)0x4F, (byte)0x67, (byte)0xDC, (byte)0xEA, (byte)0x97, (byte)0xF2, (byte)0xCF, (byte)0xCE, (byte)0xF0, (byte)0xB4, (byte)0xE6, (byte)0x73,
        (byte)0x96, (byte)0xAC, (byte)0x74, (byte)0x22, (byte)0xE7, (byte)0xAD, (byte)0x35, (byte)0x85, (byte)0xE2, (byte)0xF9, (byte)0x37, (byte)0xE8, (byte)0x1C, (byte)0x75, (byte)0xDF, (byte)0x6E,
        (byte)0x47, (byte)0xF1, (byte)0x1A, (byte)0x71, (byte)0x1D, (byte)0x29, (byte)0xC5, (byte)0x89, (byte)0x6F, (byte)0xB7, (byte)0x62, (byte)0x0E, (byte)0xAA, (byte)0x18, (byte)0xBE, (byte)0x1B,
        (byte)0xFC, (byte)0x56, (byte)0x3E, (byte)0x4B, (byte)0xC6, (byte)0xD2, (byte)0x79, (byte)0x20, (byte)0x9A, (byte)0xDB, (byte)0xC0, (byte)0xFE, (byte)0x78, (byte)0xCD, (byte)0x5A, (byte)0xF4,
        (byte)0x1F, (byte)0xDD, (byte)0xA8, (byte)0x33, (byte)0x88, (byte)0x07, (byte)0xC7, (byte)0x31, (byte)0xB1, (byte)0x12, (byte)0x10, (byte)0x59, (byte)0x27, (byte)0x80, (byte)0xEC, (byte)0x5F,
        (byte)0x60, (byte)0x51, (byte)0x7F, (byte)0xA9, (byte)0x19, (byte)0xB5, (byte)0x4A, (byte)0x0D, (byte)0x2D, (byte)0xE5, (byte)0x7A, (byte)0x9F, (byte)0x93, (byte)0xC9, (byte)0x9C, (byte)0xEF,
        (byte)0xA0, (byte)0xE0, (byte)0x3B, (byte)0x4D, (byte)0xAE, (byte)0x2A, (byte)0xF5, (byte)0xB0, (byte)0xC8, (byte)0xEB, (byte)0xBB, (byte)0x3C, (byte)0x83, (byte)0x53, (byte)0x99, (byte)0x61,
        (byte)0x17, (byte)0x2B, (byte)0x04, (byte)0x7E, (byte)0xBA, (byte)0x77, (byte)0xD6, (byte)0x26, (byte)0xE1, (byte)0x69, (byte)0x14, (byte)0x63, (byte)0x55, (byte)0x21, (byte)0x0C, (byte)0x7D
    };

    public static final String encoded = "CRIwqt4+szDbqkNY+I0qbDe3LQz0wiw0SuxBQtAM5TDdMbjCMD/venUDW9BL\n"
            + "PEXODbk6a48oMbAY6DDZsuLbc0uR9cp9hQ0QQGATyyCESq2NSsvhx5zKlLtz\n"
            + "dsnfK5ED5srKjK7Fz4Q38/ttd+stL/9WnDzlJvAo7WBsjI5YJc2gmAYayNfm\n"
            + "CW2lhZE/ZLG0CBD2aPw0W417QYb4cAIOW92jYRiJ4PTsBBHDe8o4JwqaUac6\n"
            + "rqdi833kbyAOV/Y2RMbN0oDb9Rq8uRHvbrqQJaJieaswEtMkgUt3P5Ttgeh7\n"
            + "J+hE6TR0uHot8WzHyAKNbUWHoi/5zcRCUipvVOYLoBZXlNu4qnwoCZRSBgvC\n"
            + "wTdz3Cbsp/P2wXB8tiz6l9rL2bLhBt13Qxyhhu0H0+JKj6soSeX5ZD1Rpilp\n"
            + "9ncR1tHW8+uurQKyXN4xKeGjaKLOejr2xDIw+aWF7GszU4qJhXBnXTIUUNUf\n"
            + "RlwEpS6FZcsMzemQF30ezSJHfpW7DVHzwiLyeiTJRKoVUwo43PXupnJXDmUy\n"
            + "sCa2nQz/iEwyor6kPekLv1csm1Pa2LZmbA9Ujzz8zb/gFXtQqBAN4zA8/wt0\n"
            + "VfoOsEZwcsaLOWUPtF/Ry3VhlKwXE7gGH/bbShAIKQqMqqUkEucZ3HPHAVp7\n"
            + "ZCn3Ox6+c5QJ3Uv8V7L7SprofPFN6F+kfDM4zAc59do5twgDoClCbxxG0L19\n"
            + "TBGHiYP3CygeY1HLMrX6KqypJfFJW5O9wNIF0qfOC2lWFgwayOwq41xdFSCW\n"
            + "0/EBSc7cJw3N06WThrW5LimAOt5L9c7Ik4YIxu0K9JZwAxfcU4ShYu6euYmW\n"
            + "LP98+qvRnIrXkePugS9TSOJOHzKUoOcb1/KYd9NZFHEcp58Df6rXFiz9DSq8\n"
            + "0rR5Kfs+M+Vuq5Z6zY98/SP0A6URIr9NFu+Cs9/gf+q4TRwsOzRMjMQzJL8f\n"
            + "7TXPEHH2+qEcpDKz/5pE0cvrgHr63XKu4XbzLCOBz0DoFAw3vkuxGwJq4Cpx\n"
            + "kt+eCtxSKUzNtXMn/mbPqPl4NZNJ8yzMqTFSODS4bYTBaN/uQYcOAF3NBYFd\n"
            + "5x9TzIAoW6ai13a8h/s9i5FlVRJDe2cetQhArrIVBquF0L0mUXMWNPFKkaQE\n"
            + "BsxpMCYh7pp7YlyCNode12k5jY1/lc8jQLQJ+EJHdCdM5t3emRzkPgND4a7O\n"
            + "NhoIkUUS2R1oEV1toDj9iDzGVFwOvWyt4GzA9XdxT333JU/n8m+N6hs23MBc\n"
            + "Z086kp9rJGVxZ5f80jRz3ZcjU6zWjR9ucRyjbsuVn1t4EJEm6A7KaHm13m0v\n"
            + "wN/O4KYTiiY3aO3siayjNrrNBpn1OeLv9UUneLSCdxcUqjRvOrdA5NYv25Hb\n"
            + "4wkFCIhC/Y2ze/kNyis6FrXtStcjKC1w9Kg8O25VXB1Fmpu+4nzpbNdJ9LXa\n"
            + "hF7wjOPXN6dixVKpzwTYjEFDSMaMhaTOTCaqJig97624wv79URbCgsyzwaC7\n"
            + "YXRtbTstbFuEFBee3uW7B3xXw72mymM2BS2uPQ5NIwmacbhta8aCRQEGqIZ0\n"
            + "78YrrOlZIjar3lbTCo5o6nbbDq9bvilirWG/SgWINuc3pWl5CscRcgQQNp7o\n"
            + "LBgrSkQkv9AjZYcvisnr89TxjoxBO0Y93jgp4T14LnVwWQVx3l3d6S1wlsci\n"
            + "dVeaM24E/JtS8k9XAvgSoKCjyiqsawBMzScXCIRCk6nqX8ZaJU3rZ0LeOMTU\n"
            + "w6MC4dC+aY9SrCvNQub19mBdtJUwOBOqGdfd5IoqQkaL6DfOkmpnsCs5PuLb\n"
            + "GZBVhah5L87IY7r6TB1V7KboXH8PZIYc1zlemMZGU0o7+etxZWHgpdeX6JbJ\n"
            + "Is3ilAzYqw/Hz65no7eUxcDg1aOaxemuPqnYRGhW6PvjZbwAtfQPlofhB0jT\n"
            + "Ht5bRlzF17rn9q/6wzlc1ssp2xmeFzXoxffpELABV6+yj3gfQ/bxIB9NWjdZ\n"
            + "K08RX9rjm9CcBlRQeTZrD67SYQWqRpT5t7zcVDnx1s7ZffLBWm/vXLfPzMaQ\n"
            + "YEJ4EfoduSutjshXvR+VQRPs2TWcF7OsaE4csedKUGFuo9DYfFIHFDNg+1Py\n"
            + "rlWJ0J/X0PduAuCZ+uQSsM/ex/vfXp6Z39ngq4exUXoPtAIqafrDMd8SuAty\n"
            + "EZhyY9V9Lp2qNQDbl6JI39bDz+6pDmjJ2jlnpMCezRK89cG11IqiUWvIPxHj\n"
            + "oiT1guH1uk4sQ2Pc1J4zjJNsZgoJDcPBbfss4kAqUJvQyFbzWshhtVeAv3dm\n"
            + "gwUENIhNK/erjpgw2BIRayzYw001jAIF5c7rYg38o6x3YdAtU3d3QpuwG5xD\n"
            + "fODxzfL3yEKQr48C/KqxI87uGwyg6H5gc2AcLU9JYt5QoDFoC7PFxcE3RVqc\n"
            + "7/Um9Js9X9UyriEjftWt86/tEyG7F9tWGxGNEZo3MOydwX/7jtwoxQE5ybFj\n"
            + "WndqLp8DV3naLQsh/Fz8JnTYHvOR72vuiw/x5D5PFuXV0aSVvmw5Wnb09q/B\n"
            + "owS14WzoHH6ekaWbh78xlypn/L/M+nIIEX1Ol3TaVOqIxvXZ2sjm86xRz0Ed\n"
            + "oHFfupSekdBULCqptxpFpBshZFvauUH8Ez7wA7wjL65GVlZ0f74U7MJVu9Sw\n"
            + "sZdgsLmnsQvr5n2ojNNBEv+qKG2wpUYTmWRaRc5EClUNfhzh8iDdHIsl6edO\n"
            + "ewORRrNiBay1NCzlfz1cj6VlYYQUM9bDEyqrwO400XQNpoFOxo4fxUdd+AHm\n"
            + "CBhHbyCR81/C6LQTG2JQBvjykG4pmoqnYPxDyeiCEG+JFHmP1IL+jggdjWhL\n"
            + "WQatslrWxuESEl3PEsrAkMF7gt0dBLgnWsc1cmzntG1rlXVi/Hs2TAU3RxEm\n"
            + "MSWDFubSivLWSqZj/XfGWwVpP6fsnsfxpY3d3h/fTxDu7U8GddaFRQhJ+0ZO\n"
            + "dx6nRJUW3u6xnhH3mYVRk88EMtpEpKrSIWfXphgDUPZ0f4agRzehkn9vtzCm\n"
            + "NjFnQb0/shnqTh4Mo/8oommbsBTUKPYS7/1oQCi12QABjJDt+LyUan+4iwvC\n"
            + "i0k0IUIHvk21381vC0ixYDZxzY64+xx/RNID+iplgzq9PDZgjc8L7jMg+2+m\n"
            + "rxPS56e71m5E2zufZ4d+nFjIg+dHD/ShNPzVpXizRVUERztLuak8Asah3/yv\n"
            + "wOrH1mKEMMGC1/6qfvZUgFLJH5V0Ep0n2K/Fbs0VljENIN8cjkCKdG8aBnef\n"
            + "EhITdV7CVjXcivQ6efkbOQCfkfcwWpaBFC8tD/zebXFE+JshW16D4EWXMnSm\n"
            + "/9HcGwHvtlAj04rwrZ5tRvAgf1IR83kqqiTvqfENcj7ddCFwtNZrQK7EJhgB\n"
            + "5Tr1tBFcb9InPRtS3KYteYHl3HWR9t8E2YGE8IGrS1sQibxaK/C0kKbqIrKp\n"
            + "npwtoOLsZPNbPw6K2jpko9NeZAx7PYFmamR4D50KtzgELQcaEsi5aCztMg7f\n"
            + "p1mK6ijyMKIRKwNKIYHagRRVLNgQLg/WTKzGVbWwq6kQaQyArwQCUXo4uRty\n"
            + "zGMaKbTG4dns1OFB1g7NCiPb6s1lv0/lHFAF6HwoYV/FPSL/pirxyDSBb/FR\n"
            + "RA3PIfmvGfMUGFVWlyS7+O73l5oIJHxuaJrR4EenzAu4Avpa5d+VuiYbM10a\n"
            + "LaVegVPvFn4pCP4U/Nbbw4OTCFX2HKmWEiVBB0O3J9xwXWpxN1Vr5CDi75Fq\n"
            + "NhxYCjgSJzWOUD34Y1dAfcj57VINmQVEWyc8Tch8vg9MnHGCOfOjRqp0VGyA\n"
            + "S15AVD2QS1V6fhRimJSVyT6QuGb8tKRsl2N+a2Xze36vgMhw7XK7zh//jC2H";
}
