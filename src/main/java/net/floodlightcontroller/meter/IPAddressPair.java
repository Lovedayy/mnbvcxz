package net.floodlightcontroller.meter;

import org.projectfloodlight.openflow.types.IPv4Address;

import java.util.Objects;

public class IPAddressPair {

    private final IPv4Address srcIP;
    private final IPv4Address dstIP;

    public IPAddressPair(IPv4Address srcIP, IPv4Address dstIP) {
        this.srcIP = srcIP;
        this.dstIP = dstIP;
    }

    public IPv4Address getSrcIP() {
        return srcIP;
    }

    public IPv4Address getDstIP() {
        return dstIP;
    }

    public boolean equals(IPAddressPair x) {
        if (x == null) {
            return false;
        }
        if (this == x) {
            return true;
        }
        if (!this.srcIP.equals(x.srcIP)) {
            return false;
        }
        if (!this.dstIP.equals(x.dstIP)) {
            return false;
        }
        return true;
    }


    @Override
    public int hashCode() {
        return Objects.hash(srcIP, dstIP);
    }

    @Override
    public String toString() {
        return "IPAddressPair{" +
                "srcIP='" + srcIP + '\'' +
                ", dstIP='" + dstIP + '\'' +
                '}';
    }
}

