package net.floodlightcontroller.meter;

import java.util.Map;
import java.util.Set;

public class utils {

   /* public static void putIPAddressPair(Map<IPAddressPair, Integer> map, IPAddressPair ipPair, int count) {
        if (map.containsKey(ipPair)) {
            map.put(ipPair, map.get(ipPair) + count);
        } else {
            map.put(ipPair, count);
        }
    }*/

    public static void putIPAddressPair(Map<IPAddressPair, Integer> map, IPAddressPair ipPair, int count) {
        boolean found = false;
        for (Map.Entry<IPAddressPair, Integer> entry : map.entrySet()) {
            if (entry.getKey().equals(ipPair)) {
                found = true;
                map.put(entry.getKey(), entry.getValue() + count);
                break;
            }
        }
        if (!found) {
            map.put(ipPair, count);
        }
    }

    public static boolean containsIPAddressPair(Map<IPAddressPair, Integer> map, IPAddressPair ipPair) {
        for (IPAddressPair key : map.keySet()) {
            if (key.equals(ipPair)) {
                return true;
            }
        }
        return false;
    }

    public static boolean containsIPAddressPair(Set<IPAddressPair> set, IPAddressPair ipPair) {
        for (IPAddressPair element : set) {
            if (element.equals(ipPair)) {
                return true;
            }
        }
        return false;
    }


}
