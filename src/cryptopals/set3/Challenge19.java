/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cryptopals.set3;

import static cryptopals.set1.Challenge2.xor;
import cryptopals.set1.Challenge7.Message;
import cryptopals.set1.Challenge7.Message.Counter;
import cryptopals.set1.Challenge7.Mode;
import cryptopals.set2.Challenge9;
import java.util.Random;
import javax.xml.bind.DatatypeConverter;

/**
 *
 * @author balsfull
 */
public class Challenge19 {

    private static final String alpha = "zqxjkvbpygfwmucldrhs nioate";

//    public static void main(String[] args) {
//        byte[] keystream = new byte[100];
//        for(int i = 0; i < keystream.length; i++) {
//            double score = Double.NEGATIVE_INFINITY;
//            for(byte val = Byte.MIN_VALUE; val < Byte.MAX_VALUE; val++) {
//                int correct = 0;
//                for(byte[] bytes : encrypted) {
//                    if(bytes.length <= i) break;
//         //           for(int p = i; p < bytes.length; p += 16) {
//                        char c = (char)(bytes[i] ^ val);
//                        correct += alpha.indexOf(c) + 1;
//                }
//                if(score < correct) {
//                    score = correct;
//                    keystream[i] = val;
//                }
//            }
//        }
//        for(byte[] bytes : encrypted) {
//            System.out.println(new String(xor(bytes, keystream)));
//        }
//    }

    private static final byte[][] encrypted;
    private static final String[] encoded = ("SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==\n"
            + "Q29taW5nIHdpdGggdml2aWQgZmFjZXM=\n"
            + "RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==\n"
            + "RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=\n"
            + "SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk\n"
            + "T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==\n"
            + "T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=\n"
            + "UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==\n"
            + "QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=\n"
            + "T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl\n"
            + "VG8gcGxlYXNlIGEgY29tcGFuaW9u\n"
            + "QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==\n"
            + "QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=\n"
            + "QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==\n"
            + "QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=\n"
            + "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=\n"
            + "VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==\n"
            + "SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==\n"
            + "SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==\n"
            + "VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==\n"
            + "V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==\n"
            + "V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==\n"
            + "U2hlIHJvZGUgdG8gaGFycmllcnM/\n"
            + "VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=\n"
            + "QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=\n"
            + "VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=\n"
            + "V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=\n"
            + "SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==\n"
            + "U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==\n"
            + "U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=\n"
            + "VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==\n"
            + "QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu\n"
            + "SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=\n"
            + "VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs\n"
            + "WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=\n"
            + "SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0\n"
            + "SW4gdGhlIGNhc3VhbCBjb21lZHk7\n"
            + "SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=\n"
            + "VHJhbnNmb3JtZWQgdXR0ZXJseTo=\n"
            + "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=").split("\n");

    private static final byte[] ckey = new byte[16];

    static {
        new Random().nextBytes(ckey);
        encrypted = new byte[encoded.length][];
        for(int i = 0; i < encoded.length; i++) {
            Message message = new Message(Challenge9.padMultiple(DatatypeConverter.parseBase64Binary(encoded[i]), 16));
            message.encrypt(ckey, new byte[8], Counter.getDefault(8), Mode.CTR);
//            message.encrypt(ckey, new byte[8], new Counter(8) {
//                @Override
//                public void increment() {
//                }
//            }, Mode.CTR);
            encrypted[i] = message.getData();
        }
    }
}
