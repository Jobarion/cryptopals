/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cryptopals.set5;

/**
 *
 * @author Jonas
 */
public class Tuple<K, V> {

    public final K k;
    public final V v;

    public Tuple(K k, V v) {
        this.k = k;
        this.v = v;
    }
}
