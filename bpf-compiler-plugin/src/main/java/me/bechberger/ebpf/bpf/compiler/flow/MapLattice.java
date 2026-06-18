package me.bechberger.ebpf.bpf.compiler.flow;

import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Pointwise lifting of an element lattice {@code V} to a map lattice {@code K → V}
 * (Nielson/Nielson/Hankin §2.3). A "missing" key behaves as {@code V.bottom()}.
 *
 * <p>Two abstract environments {@code E₁} and {@code E₂} are joined keywise:
 * {@code (E₁ ⊔ E₂)(k) = E₁(k) ⊔ E₂(k)}. Order: {@code E₁ ⊑ E₂} iff for every key the
 * pointwise {@code leq} holds.
 *
 * <p>Instances are returned as immutable views: the solver clones via {@link #put} /
 * {@link #remove} which return a new {@code Env}. This keeps stored lattice elements safe
 * to share across program points.
 */
public final class MapLattice<K, V> implements Lattice<MapLattice.Env<K, V>> {

    private final Lattice<V> elem;

    public MapLattice(Lattice<V> elem) {
        this.elem = elem;
    }

    public Lattice<V> element() { return elem; }

    public Env<K, V> empty() { return new Env<>(elem, Collections.emptyMap()); }

    public Env<K, V> singleton(K key, V value) {
        var m = new LinkedHashMap<K, V>();
        m.put(key, value);
        return new Env<>(elem, Collections.unmodifiableMap(m));
    }

    @Override public Env<K, V> bottom() { return empty(); }

    @Override
    public Env<K, V> join(Env<K, V> a, Env<K, V> b) {
        if (a == b) return a;
        if (a.isEmpty()) return b;
        if (b.isEmpty()) return a;
        var out = new LinkedHashMap<K, V>(a.map);
        for (var e : b.map.entrySet()) {
            var existing = out.get(e.getKey());
            out.put(e.getKey(), existing == null ? e.getValue() : elem.join(existing, e.getValue()));
        }
        return new Env<>(elem, Collections.unmodifiableMap(out));
    }

    @Override
    public Env<K, V> meet(Env<K, V> a, Env<K, V> b) {
        if (a == b) return a;
        var out = new LinkedHashMap<K, V>();
        for (var e : a.map.entrySet()) {
            var other = b.map.get(e.getKey());
            if (other != null) out.put(e.getKey(), elem.meet(e.getValue(), other));
        }
        return new Env<>(elem, Collections.unmodifiableMap(out));
    }

    @Override
    public boolean leq(Env<K, V> a, Env<K, V> b) {
        for (var e : a.map.entrySet()) {
            var rhs = b.map.get(e.getKey());
            if (rhs == null) {
                // missing in b ≡ bottom; a ⊑ b iff a's value is bottom too
                if (!elem.leq(e.getValue(), elem.bottom())) return false;
            } else if (!elem.leq(e.getValue(), rhs)) {
                return false;
            }
        }
        return true;
    }

    @Override
    public Env<K, V> widen(Env<K, V> old, Env<K, V> incoming) {
        if (old == incoming) return old;
        var out = new LinkedHashMap<K, V>(old.map);
        for (var e : incoming.map.entrySet()) {
            var existing = out.get(e.getKey());
            out.put(e.getKey(), existing == null ? e.getValue() : elem.widen(existing, e.getValue()));
        }
        return new Env<>(elem, Collections.unmodifiableMap(out));
    }

    /**
     * Immutable abstract environment: a finite map from keys to lattice values.
     * Missing keys conceptually map to {@code elem.bottom()}.
     */
    public static final class Env<K, V> {
        private final Lattice<V> elem;
        private final Map<K, V> map;

        Env(Lattice<V> elem, Map<K, V> map) {
            this.elem = elem;
            this.map = map;
        }

        public V get(K key) {
            var v = map.get(key);
            return v == null ? elem.bottom() : v;
        }

        public boolean containsKey(K key) { return map.containsKey(key); }

        public boolean isEmpty() { return map.isEmpty(); }

        public Env<K, V> put(K key, V value) {
            var m = new LinkedHashMap<>(map);
            m.put(key, value);
            return new Env<>(elem, Collections.unmodifiableMap(m));
        }

        public Env<K, V> remove(K key) {
            if (!map.containsKey(key)) return this;
            var m = new LinkedHashMap<>(map);
            m.remove(key);
            return new Env<>(elem, Collections.unmodifiableMap(m));
        }

        public Map<K, V> asMap() { return map; }

        @Override public String toString() { return map.toString(); }

        @Override public boolean equals(Object o) {
            return o instanceof Env<?, ?> e && map.equals(e.map);
        }

        @Override public int hashCode() { return map.hashCode(); }
    }

    /** Build an env from a plain mutable map (used at analysis seed time). */
    public Env<K, V> fromMap(Map<K, V> seed) {
        return new Env<>(elem, Collections.unmodifiableMap(new LinkedHashMap<>(seed)));
    }

    /** Convert env back to a mutable map (used by transfer functions). */
    public Map<K, V> toMutable(Env<K, V> env) {
        return new HashMap<>(env.map);
    }
}
