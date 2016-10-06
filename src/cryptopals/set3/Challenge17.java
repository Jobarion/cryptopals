/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cryptopals.set3;

import cryptopals.set1.Challenge7;
import cryptopals.set1.Challenge7.Message;
import cryptopals.set1.Challenge7.Message.Counter;
import cryptopals.set1.Challenge7.Mode;
import static cryptopals.set1.Challenge7.flip;
import javax.xml.bind.DatatypeConverter;

/**
 *
 * @author balsfull
 */
public class Challenge17 {
    
//    public static void main(String[] args) {
//        Message message = new Message(encrypted);
//        message.decrypt("YELLOW SUBMARINE".getBytes(), new byte[8], new CPalsCounter(8), Mode.CTR);
//        System.out.println(new String(message.getData()));
//    }
    
    private static final class CPalsCounter extends Counter {

        public CPalsCounter(int length) {
            super(length);
        }

        @Override
        public void increment() {
            Challenge7.flip(this.getValue());
            Challenge7.increment(this.getValue());
            Challenge7.flip(this.getValue());
        }
        
    }
    
    private static final byte[] encrypted = DatatypeConverter.parseBase64Binary("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==");
}
