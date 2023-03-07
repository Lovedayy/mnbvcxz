package net.floodlightcontroller.example2;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.packet.*;
import net.floodlightcontroller.staticentry.IStaticEntryPusherService;
import org.projectfloodlight.openflow.protocol.OFFactory;
import org.projectfloodlight.openflow.protocol.OFFlowAdd;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

public class Test implements IOFMessageListener, IFloodlightModule {
    protected static Logger logger;
    protected IFloodlightProviderService floodlightProvider;
    protected IStaticEntryPusherService staticEntryPusherService;
    private int packetCount=0;
    @Override
    public String getName() {
        return Test.class.getSimpleName();
    }

    @Override
    public boolean isCallbackOrderingPrereq(OFType type, String name) {
        return false;
    }

    @Override
    public boolean isCallbackOrderingPostreq(OFType type, String name) {
        return false;
    }

    @Override
    public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
        switch (msg.getType()) {
            case PACKET_IN:
                Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
                logger.info("Ethernet: Source MAC:" + eth.getSourceMACAddress() + ",Destination MAC:" + eth.getDestinationMACAddress());
                if (eth.getEtherType() == EthType.ARP) {
                    ARP arp = (ARP) eth.getPayload();
                    logger.info("ARP: OpCode:" + arp.getOpCode());
                }
                else if (eth.getEtherType() == EthType.IPv4) {
                    IPv4 ipv4 = (IPv4) eth.getPayload();
                    logger.info("IPv4: Source IPv4 address:" + ipv4.getSourceAddress() + ",destination IPv4 address:" + ipv4.getDestinationAddress());
                    if (ipv4.getProtocol() == IpProtocol.TCP) {
                        TCP tcp = (TCP) ipv4.getPayload();
                        logger.info("TCP:TCP source port:" + tcp.getSourcePort() + ",TCP destination port:" + tcp.getDestinationPort());
                    } else if (ipv4.getProtocol() == IpProtocol.UDP) {
                        UDP udp = (UDP) ipv4.getPayload();
                        logger.info("UDP:UDP source port:" + udp.getSourcePort() + ",UDP destination port:" + udp.getDestinationPort());
                    }
                    else if (ipv4.getProtocol() == IpProtocol.ICMP) {
                        ICMP icmp = (ICMP) ipv4.getPayload();
                        dropPacket(sw);
                        logger.info("Drop ICMP:ICMP type:" + icmp.getIcmpType() + ", ICMP code:" + icmp.getIcmpCode());
                    }
                }
                packetCount++;
                break;
            default:
                break;
        }
        return Command.CONTINUE;
    }
    private void dropPacket(IOFSwitch sw) {
        OFFactory ofFactory = sw.getOFFactory();
        Match match = ofFactory.buildMatch()
                .setExact(MatchField.ETH_TYPE, EthType.IPv4)
                .setExact(MatchField.IP_PROTO, IpProtocol.ICMP)
                .build();
        OFFlowAdd flowAdd = ofFactory.buildFlowAdd()
                .setPriority(32767)
                .setIdleTimeout(0)
                .setHardTimeout(0)
                .setMatch(match)
                .build();
        staticEntryPusherService.addFlow("flow"+packetCount, flowAdd, sw.getId());
    }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleServices() {
        return null;
    }

    @Override
    public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
        return null;
    }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
        Collection<Class<? extends IFloodlightService>> l =
                new ArrayList<Class<? extends IFloodlightService>>();
        l.add(IFloodlightProviderService.class);
        l.add(IStaticEntryPusherService.class);
        return l;
    }

    @Override
    public void init(FloodlightModuleContext context) throws FloodlightModuleException {
        logger = LoggerFactory.getLogger(Test.class);
        floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
        staticEntryPusherService = context.getServiceImpl(IStaticEntryPusherService.class);
    }

    @Override
    public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
        floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
    }
}
