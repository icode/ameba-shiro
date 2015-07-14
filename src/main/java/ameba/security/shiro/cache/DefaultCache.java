package ameba.security.shiro.cache;

import com.google.common.collect.Maps;
import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheException;

import java.util.Collection;
import java.util.Map;
import java.util.Set;

/**
 * @author icode
 */
public class DefaultCache<K, V> implements Cache<K, V> {

    private static final String CACHE_PRE_KEY = DefaultCache.class.getName() + ".";

    private String cacheName;
    private Map<K, V> caches;

    public DefaultCache(String name) {
        cacheName = CACHE_PRE_KEY + name;
        caches = ameba.cache.Cache.get(cacheName);
        if (caches == null) {
            caches = Maps.newLinkedHashMap();
        }
    }

    @Override
    public V get(K key) throws CacheException {
        return caches.get(key);
    }

    @Override
    public V put(K key, V value) throws CacheException {
        try {
            return caches.put(key, value);
        } finally {
            flush();
        }
    }

    @Override
    public V remove(K key) throws CacheException {
        try {
            return caches.remove(key);
        } finally {
            flush();
        }
    }

    protected void flush() {
        ameba.cache.Cache.syncSet(cacheName, caches);
    }

    @Override
    public void clear() throws CacheException {
        caches.clear();
        ameba.cache.Cache.delete(cacheName);
    }

    @Override
    public int size() {
        return caches.size();
    }

    @Override
    public Set<K> keys() {
        return caches.keySet();
    }

    @Override
    public Collection<V> values() {
        return caches.values();
    }
}
