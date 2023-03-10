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

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        IPAddressPair that = (IPAddressPair) o;
        return Objects.equals(srcIP, that.srcIP) &&
                Objects.equals(dstIP, that.dstIP);
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

