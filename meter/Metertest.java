package net.floodlightcontroller.meter;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.packet.*;
import net.floodlightcontroller.staticentry.IStaticEntryPusherService;
import org.projectfloodlight.openflow.protocol.*;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.instruction.OFInstruction;
import org.projectfloodlight.openflow.protocol.instruction.OFInstructionMeter;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.protocol.meterband.OFMeterBand;
import org.projectfloodlight.openflow.protocol.meterband.OFMeterBandDrop;
import org.projectfloodlight.openflow.types.*;
import org.python.constantine.platform.IPProto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.core.util.AppCookie;
import net.floodlightcontroller.devicemanager.SwitchPort;
import net.floodlightcontroller.statistics.IStatisticsService;
import net.floodlightcontroller.statistics.SwitchPortBandwidth;
import net.floodlightcontroller.threadpool.IThreadPoolService;
import net.floodlightcontroller.topology.ITopologyService;

public class Metertest implements IOFMessageListener, IFloodlightModule, IMetertestService {
	
	protected static Logger logger;
	protected ITopologyService topology;             //拓扑管理模块的接口
	protected IThreadPoolService threadPoolService;  //线程池
	protected IOFSwitchService ofswitch;             //交换机管理模块的接口
	protected IStatisticsService statistics;         //统计模块的接口

	protected IFloodlightProviderService floodlightProvider;
	protected IStaticEntryPusherService staticEntryPusherService;
	
	private static Set<DatapathId> swid;           //存储拓扑中的所有交换机id
	private static Set<SwitchPort> switchports;    //存储交换机与主机相连的端口
	private static Set<SwitchPort> addFlowHistory = new HashSet<SwitchPort>(); //记录下发过的流表项
	
	private static final int Period = 6;   //线程间隔时间
	private static long MAX = 15000;        //流量阈值，单位为kbit/s
	private static long MeterId = 0;       //
	private static long rateLimit = 5000;   //限速速率
	private static long speed = 10000; //限速速率

	private int packetCount=0;


	@Override
	public String getName() {
		// TODO Auto-generated method stub
		return "Metertest";
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
        l.add(IMetertestService.class);
        return l;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		Map<Class<? extends IFloodlightService>, IFloodlightService> m = new HashMap<Class<? extends IFloodlightService>, IFloodlightService>();
        m.put(IMetertestService.class, this);
        return m;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
        l.add(ITopologyService.class);
		l.add(IOFSwitchService.class);
		l.add(IStatisticsService.class);
		l.add(IFloodlightProviderService.class);
		return l;
	}

	@Override
	public void init(FloodlightModuleContext context) throws FloodlightModuleException {
		topology = context.getServiceImpl(ITopologyService.class);
		threadPoolService = context.getServiceImpl(IThreadPoolService.class);
		ofswitch = context.getServiceImpl(IOFSwitchService.class);
		statistics = context.getServiceImpl(IStatisticsService.class);
		logger = LoggerFactory.getLogger(Metertest.class);
		floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
	}

	@Override
	public synchronized void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
		//定义线程类，每隔Period秒执行一次
		threadPoolService.getScheduledExecutor().scheduleAtFixedRate(new GetInfo(), 1, Period, TimeUnit.SECONDS);
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
	}

	//国际学院网络2001班匡子晗 学号202021190009
	@Override
	public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		switch (msg.getType()) {
			case PACKET_IN:
				Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
				if (eth.getEtherType() == EthType.IPv4) {
					IPv4 ipv4 = (IPv4) eth.getPayload();
					logger.info("IPv4: Source IPv4 address:" + ipv4.getSourceAddress() + ",destination IPv4 address:" + ipv4.getDestinationAddress());
					//如果是TCP数据包，且目的地是10.0.0.4，源地址是10.0.0.3,那么对此采取ratelimit操作
					if (ipv4.getProtocol() == IpProtocol.TCP && ipv4.getDestinationAddress().equals(IPv4Address.of("10.0.0.4"))
							&& ipv4.getSourceAddress().equals(IPv4Address.of("10.0.0.3"))) {
						TCP tcp = (TCP) ipv4.getPayload();
						addMeter(sw,rateLimit);
						//从3端口来的
						addMFlow(sw,OFPort.of(3));
						logger.info("TCP:TCP source port:" + tcp.getSourcePort() + ",TCP destination port:" + tcp.getDestinationPort());
					}
					else if (ipv4.getProtocol() == IpProtocol.UDP) {
						UDP udp = (UDP) ipv4.getPayload();
						logger.info("UDP:UDP source port:" + udp.getSourcePort() + ",UDP destination port:" +
								udp.getDestinationPort());
					}
				}
				packetCount++;
				break;
			default:
				break;
		}
		return Command.CONTINUE;
	}
	
	protected class GetInfo implements Runnable{
		
		public void run() {
			System.out.println("Start!");
			if(!ofswitch.getAllSwitchDpids().isEmpty()) {
				getSwitchPorts();
				getPortFlows();
			}
		}
	}
	
	@Override
	//获得拓扑中所有（边缘交换机，其边缘端口）的集合
	public void getSwitchPorts() {
		//得到所有交换机id
		swid = new HashSet<DatapathId>(ofswitch.getAllSwitchDpids());
		switchports = new HashSet<SwitchPort>();
		for(DatapathId dpid : swid) {
			//得到每个交换机的所有端口
			Set<OFPort> ports = new HashSet<OFPort>(topology.getPorts(dpid));
			for(OFPort port : ports) {
				//判断交换机端口是否是边缘端口(边缘端口为直接连接主机的端口)
				if(topology.isEdge(dpid, port)) {
					//加到边缘交换机的存储switchports里面去
					switchports.add(new SwitchPort(dpid,port));
				}
			}
		}
	}
	@Override
	//给所有接收流量速率超过阈值的（边缘交换机，其边缘端口）下发计量表项和流表项
	public void getPortFlows() {
		for(SwitchPort sp : switchports) {
			SwitchPortBandwidth data = statistics.getBandwidthConsumption(sp.getNodeId(), sp.getPortId());
			if(data != null) {
				//端口接收流量和发送流量速率，单位为kbit/s
				long RX = data.getBitsPerSecondRx().getValue()/1000;
				long TX = data.getBitsPerSecondTx().getValue()/1000;
				System.out.println("交换机" + sp.getNodeId() + "的" + sp.getPortId() + "端口接收流量:" + RX + "Kbit/s");
				System.out.println("交换机" + sp.getNodeId() + "的" + sp.getPortId() + "端口发送流量:" + TX + "Kbit/s");
				
				//判断流表项是否已经下发
				if(!addFlowHistory.contains(sp)) {
					//如果大于rateLimit（5mb），且还是从3端口发的
					if(RX >= rateLimit && sp.getPortId().equals(OFPort.of(3))) {
						//h3对h4发送的UDP流量被限制在5mb
						addMeter(ofswitch.getSwitch(sp.getNodeId()), (long)0);
                        addFlow(ofswitch.getSwitch(sp.getNodeId()), IPv4Address.of("10.0.0.3"), IPv4Address.of("10.0.0.4"));
						addFlowHistory.add(sp);
					}
					//如果大于MAX（15mb），且还是从2端口发的
					if(RX >= MAX && sp.getPortId().equals(OFPort.of(2))) {
						//下发meter表，将速度限制在0
                        addMeter(ofswitch.getSwitch(sp.getNodeId()), speed);
                        //下发指定该meter表的流表项
						addMMFlow(ofswitch.getSwitch(sp.getNodeId()), IPv4Address.of("10.0.0.2"), IPv4Address.of("10.0.0.4"));
						addFlowHistory.add(sp);
					}
				}
			}
		}
	}


	public static void addMeter(IOFSwitch sw, Long rateLimit){
		MeterId++;
		logger.info("enter add meter()");
		//设置OpenFlow版本
		OFFactory my13Factory = OFFactories.getFactory(OFVersion.OF_13);
		//设置flag
		Set<OFMeterFlags> flags = new HashSet<OFMeterFlags>();
		flags.add(OFMeterFlags.KBPS);

		//创建一个band
		OFMeterBandDrop bandDrop = my13Factory.meterBands().buildDrop()														   
														   .setRate(rateLimit)	// kbps
														   .build();
		
		logger.info("create band");
		
		//设置bands
		List<OFMeterBand> bands = new ArrayList<OFMeterBand>();
		bands.add(0,bandDrop);
		logger.info("add band to bands");
		
		//创建一个Meter Modification Message发给交换机
		OFMeterMod meterMod = my13Factory.buildMeterMod()
										 .setMeterId(MeterId)
										 .setCommand(OFMeterModCommand.ADD)
										 .setFlags(flags)
										 .setMeters(bands)									
										 .build();
		logger.info("create meterMod msg");
	
		sw.write(meterMod);
		logger.info("add meter" + MeterId + " to meter table");
	}

	//通过ip地址来添加流表项（h3对h4发送的UDP流量不能超过5mb）
	public static void addFlow(IOFSwitch sw, IPv4Address IPv4_SRC, IPv4Address IPv4_DST)
	{
		OFFlowMod.Builder fmb2 = sw.getOFFactory().buildFlowAdd();
		//设置匹配域
		Match.Builder mb2 = sw.getOFFactory().buildMatch();
		mb2.setExact(MatchField.ETH_TYPE, EthType.IPv4)
				.setExact(MatchField.IPV4_SRC, IPv4_SRC)
				.setExact(MatchField.IPV4_DST, IPv4_DST)
				//匹配h3发往h4的UDP包
				.setExact(MatchField.IP_PROTO, IpProtocol.UDP);
		//设置流表项
		fmb2.setHardTimeout(0)
				.setIdleTimeout(0)
				.setPriority(5)
				.setMatch(mb2.build());
		if(sw.write(fmb2.build())) {
			logger.info("add flow entry success");
		}
		else {
			logger.info("add flow entry failed");
		}
	}
	public static void addMFlow(IOFSwitch sw, OFPort in_port){
		OFFlowMod.Builder fmb = sw.getOFFactory().buildFlowAdd();
		//匹配域
        Match.Builder mb = sw.getOFFactory().buildMatch();
        mb.setExact(MatchField.IN_PORT, in_port);
        //指令与动作
		OFFactory myOF13Factory = OFFactories.getFactory(OFVersion.OF_13);
        List<OFAction> actions = new ArrayList<OFAction>();
        List<OFInstruction> instructions = new ArrayList<OFInstruction>();

		OFInstructionMeter meter = myOF13Factory.instructions().buildMeter()
                .setMeterId(MeterId)
                .build();
		instructions.add(meter);

		OFAction output = myOF13Factory.actions().buildOutput()
				//对于.setPort(OFPort.of(2))，是从2端口转出去，但实际要根据topo情况不同而改变
				//controller是交给控制器处理
				//此处为从4端口转出去
        		    .setPort(OFPort.of(4))
        		    .build();
		actions.add(output);

		instructions.add((OFInstruction) myOF13Factory.instructions().applyActions(actions)) ;

        //流表项
        fmb.setHardTimeout(0)
				.setIdleTimeout(0)
                .setPriority(5)
                .setMatch(mb.build());
        fmb.setInstructions(instructions);
       
        if(sw.write(fmb.build())) {
              logger.info("M：add flow entry success");
          }
          else {
              logger.info("M：add flow entry failed");
          }
	}
	public static void addMMFlow(IOFSwitch sw, IPv4Address IPv4_SRC, IPv4Address IPv4_DST)
	{
		OFFlowMod.Builder fmb1 = sw.getOFFactory().buildFlowAdd();
		//匹配域
		Match.Builder mb1 = sw.getOFFactory().buildMatch();
		mb1.setExact(MatchField.ETH_TYPE, EthType.IPv4)
			.setExact(MatchField.IPV4_SRC, IPv4_SRC)
				.setExact(MatchField.IPV4_DST, IPv4_DST)
				.setExact(MatchField.IP_PROTO, IpProtocol.UDP);

		//指令与动作
		OFFactory myOF13Factory1 = OFFactories.getFactory(OFVersion.OF_13);
		List<OFAction> actions = new ArrayList<OFAction>();
		List<OFInstruction> instructions = new ArrayList<OFInstruction>();

		OFInstructionMeter meter = myOF13Factory1.instructions().buildMeter()
				.setMeterId(MeterId)
				.build();
		instructions.add(meter);

		OFAction output = myOF13Factory1.actions().buildOutput()
				.setPort(OFPort.of(4))
				.build();
		actions.add(output);

		instructions.add((OFInstruction) myOF13Factory1.instructions().applyActions(actions)) ;

		//流表项
		fmb1.setHardTimeout(0)
				.setIdleTimeout(0)
				.setPriority(5)
				.setMatch(mb1.build());
		fmb1.setInstructions(instructions);

		if(sw.write(fmb1.build())) {
			logger.info("MM:add flowentry success");
		}
		else {
			logger.info("MM:add flowentry1 failed");
		}
	}


}

