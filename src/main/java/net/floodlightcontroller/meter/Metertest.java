package net.floodlightcontroller.meter;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.util.*;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.projectfloodlight.openflow.protocol.OFFlowMod;
import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.SwitchPort;
import net.floodlightcontroller.statistics.IStatisticsService;
import net.floodlightcontroller.statistics.SwitchPortBandwidth;
import net.floodlightcontroller.threadpool.IThreadPoolService;
import net.floodlightcontroller.topology.ITopologyService;

import static net.floodlightcontroller.core.internal.Controller.switchService;

import static net.floodlightcontroller.meter.utils.*;

public class Metertest implements IOFMessageListener, IFloodlightModule, IMetertestService {

	protected static Logger logger;
	protected ITopologyService topology;             //拓扑管理模块的接口
	protected IThreadPoolService threadPoolService;  //线程池
	protected IOFSwitchService ofswitch;             //交换机管理模块的接口
	protected IStatisticsService statistics;         //统计模块的接口

	protected IFloodlightProviderService floodlightProvider;
	protected static IStaticEntryPusherService staticEntryPusherService;

	private static Set<DatapathId> swid;           //存储拓扑中的所有交换机id
	private static Set<SwitchPort> switchports;    //存储交换机与主机相连的端口
	private static Set<SwitchPort> addFlowHistory = new HashSet<SwitchPort>(); //记录下发过的流表项
	private static Map<IPAddressPair, Integer> ipCountMap = new HashMap<>();//用于记录IP地址对出现次数的Map
	private Set<IPAddressPair> maliciousIPSet = new HashSet<>(); // 存储恶意IP地址对的集合
	private Set<IPAddressPair> historyIPSet = new HashSet<>(); // 存储历史IP地址对的集合
	private Set<IPAddressPair> warningIPSet = new HashSet<>(); // 存储预警IP地址对的集合
	//private Map<IPAddressPair, Integer> ipPairCounter = new HashMap<>(); //统计每个 IP 地址对出现的次数

	public static final int NORMAL_TO_HISTORY = 0; // normal状态下的流表项ID，用于将IP地址对从normal状态转变为history状态
	public static final int NORMAL_TO_DEFAULT = 1; // normal状态下的流表项ID，用于将IP地址对从normal状态转变为default状态
	public static final int WARNING_TO_LIMIT = 2; // defence状态下的流表项ID，用于将IP地址对从warning状态转变为limit状态
	public static final int MALICIOUS_TO_DROP = 3; // defence状态下的流表项ID，用于将IP地址对从defence状态转变为drop状态
	//public static final int IP_COUNT_MAP_CLEAR_INTERVAL=90000;//15mins
	// Parameters
	private static final int attackThreshold = 140;     // IP对出现次数的攻击阈值
	private static final int normalThreshold = 120;     // IP对出现次数的正常阈值
	private static final int attack = 10000;       // 流量阈值，单位kbit/s
	private static final int Period = 2;                    // 链路流量检测线程的执行周期
	private static final int timeThreshold = 5000;         // Edge port traffic check interval in milliseconds
	private static long MeterId = 0;              //计量表号，下发计量表时，初值需设为1
	private static final long rateLimit = 5000;                  //计量表限速后的速率

	private static int counter = 0; // 状态切换计数器，初始值为0

	private int status = 0;// 0=normal,1=defence

	private static final int COUNTER_THRESHOLD = 10;  // 计数器的阈值
	private static int packetCount = 0;  // 统计接收的数据包数目

	//private long lastUpdateTime = 0;//打点记录时间，


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
		l.add(IStaticEntryPusherService.class);
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
		staticEntryPusherService = context.getServiceImpl(IStaticEntryPusherService.class);
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
					String srcIp = ipv4.getSourceAddress().toString();
					String dstIp = ipv4.getDestinationAddress().toString();

					IPv4Address srcIP = IPv4Address.of(srcIp);
					IPv4Address dstIP = IPv4Address.of(dstIp);
					IPAddressPair ipPair = new IPAddressPair(srcIP, dstIP);

					logger.info("IPv4: Source IPv4 address:" + ipv4.getSourceAddress() + ",destination IPv4 address:" + ipv4.getDestinationAddress());

/*					TimerTask clearTask = new TimerTask() {
						@Override
						public void run() {
							ipCountMap.clear();
							log.info("Clear ipCountMap");
						}
					};*/

					int count = containsIPAddressPair(ipCountMap,ipPair) ? ipCountMap.get(ipPair) + 1 : 1;
					//ipCountMap.put(ipPair, count);
					putIPAddressPair(ipCountMap,ipPair,count);
					System.out.println("ipPair：" + ipPair.getSrcIP() + "到" + ipPair.getDstIP() + "出现第" + count + "次");
					classifyFlow(ipPair, count,sw);
				}
				packetCount++;
				break;
			default:
				break;
		}
		return Command.CONTINUE;
	}

	protected class GetInfo implements Runnable {

		public void run() {
			System.out.println("Start!");
			if (!ofswitch.getAllSwitchDpids().isEmpty()) {
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
		for (DatapathId dpid : swid) {
			//得到每个交换机的所有端口
			Set<OFPort> ports = new HashSet<OFPort>(topology.getPorts(dpid));
			for (OFPort port : ports) {
				//判断交换机端口是否是边缘端口(边缘端口为直接连接主机的端口)
				if (topology.isEdge(dpid, port)) {
					//加到边缘交换机的存储switchports里面去
					switchports.add(new SwitchPort(dpid, port));
				}
			}
		}
	}

	@Override
	//给所有接收流量速率超过阈值的（边缘交换机，其边缘端口）下发计量表项和流表项
	public void getPortFlows() {
/*		// 记录当前轮到的交换机编号，初始值为0
		int currentSwitchIndex = 0;*/

		// 记录每个交换机是否超过阈值的状态，初始值为false
		boolean RXflag = false;
		boolean TXflag = false;

		for (SwitchPort sp : switchports) {
			SwitchPortBandwidth data = statistics.getBandwidthConsumption(sp.getNodeId(), sp.getPortId());
			if (data != null) {
				//端口接收流量和发送流量速率，单位为kbit/s
				long RX = data.getBitsPerSecondRx().getValue() / 1000;
				long TX = data.getBitsPerSecondTx().getValue() / 1000;
				System.out.println("交换机" + sp.getNodeId() + "的" + sp.getPortId() + "端口接收流量:" + RX + "Kbit/s");
				System.out.println("交换机" + sp.getNodeId() + "的" + sp.getPortId() + "端口发送流量:" + TX + "Kbit/s");

				// 判断流量是否超过阈值
				//sw1的接收流量
				if (RX > attack) {
					RXflag = true;
				}
				//sw2的发送流量
				if (TX > attack) {
					TXflag = true;
				}

				// 判断流量是否超过阈值
				if (TXflag && RXflag) {
					//packetCount++;
					//System.out.println("超过阈值" + packetCount + "次");
					status = 1;
					System.out.println("检测到超出阈值，将系统状态设置为 防御 状态");
					counter = 0; // 重置计数器
				} else {
					if (counter > 10) {
						// 如果系统之前已经处于防御状态，并且连续10个时间间隔内都没有超过流量阈值，则将系统状态设置为正常状态
						status = 0;
						System.out.println("系统状态为 正常 ");
					}
					counter++; // 计数器加1
				}
			}
		}
	}

	public void writeIPSetToFile(Set<IPAddressPair> ipSet, String fileName) {
		try {
			FileWriter fileWriter = new FileWriter(fileName);
			BufferedWriter bufferedWriter = new BufferedWriter(fileWriter);
			for (IPAddressPair ipPair : ipSet) {
				bufferedWriter.write(ipPair.toString());
				bufferedWriter.newLine();
			}
			bufferedWriter.close();
			fileWriter.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	//情况分类
	public void classifyFlow(IPAddressPair ipPair, int count, IOFSwitch sw) {
		switch (status) {
			//normal
			case 0:
				if (count > normalThreshold && !containsIPAddressPair(maliciousIPSet,ipPair)) {

					addFlow(ipPair, NORMAL_TO_HISTORY,sw);
				} else {

					addFlow(ipPair, NORMAL_TO_DEFAULT,sw);
				}
				break;

			//defence
			case 1:
				if (count > attackThreshold) {
					if (containsIPAddressPair(historyIPSet,ipPair)) {

						addFlow(ipPair, WARNING_TO_LIMIT,sw);
					} else {

						addFlow(ipPair, MALICIOUS_TO_DROP,sw);
						maliciousIPSet.add(ipPair);
					}
				} else {
					//System.out.println("模式： NORMAL_TO_DEFAULT");
					addFlow(ipPair, NORMAL_TO_DEFAULT,sw);
				}
				break;

			default:
				//System.out.println("模式： NORMAL_TO_DEFAULT");
				addFlow(ipPair, NORMAL_TO_DEFAULT,sw);
				break;
		}
	}

	//原版contain不能用
	private void addFlow(IPAddressPair ipPair, int flowType, IOFSwitch sw) {
		//IOFSwitch sw = switchService.getActiveSwitch(DatapathId.of(ipPair.getSrcIP().getInt())); // get the source switch
		IPv4Address ipv4_src = ipPair.getSrcIP(); // get the source IP address
		IPv4Address ipv4_dst = ipPair.getDstIP(); // get the destination IP address

		switch (flowType) {
			case NORMAL_TO_HISTORY:
				if (containsIPAddressPair(ipCountMap,ipPair)){
					//ipPairCounter.containsKey(ipPair)
					System.out.println("模式：NORMAL_TO_HISTORY");
					int count = ipCountMap.get(ipPair);
					if (count > normalThreshold && !containsIPAddressPair(maliciousIPSet,ipPair)) {
						putIPAddressPair(ipCountMap,ipPair,0);
						//ipPairCounter.put(ipPair, 0); // reset count to 0
						historyIPSet.add(ipPair); // add to history IP set
						writeIPSetToFile(historyIPSet, "historyIPSet.txt");
						logger.info("IP pair " + ipPair + " added to history IP set");
					}
				}
				break;

			case NORMAL_TO_DEFAULT:
				if (containsIPAddressPair(ipCountMap,ipPair)) {
					System.out.println("模式： NORMAL_TO_DEFAULT");
					int count = ipCountMap.get(ipPair);
					if (count <= normalThreshold || containsIPAddressPair(maliciousIPSet,ipPair)) {
						putIPAddressPair(ipCountMap,ipPair,0); // reset count to 0
						defaultFlow(sw, ipv4_dst); // forward using default flow
					}
				}
				break;

			case WARNING_TO_LIMIT:
				if (containsIPAddressPair(ipCountMap,ipPair)) {
					System.out.println("模式： WARNING_TO_LIMIT");
					int count = ipCountMap.get(ipPair);
					if (count > attackThreshold) {
						if (containsIPAddressPair(historyIPSet,ipPair)) {
							warningIPSet.add(ipPair); // add to warning IP set
							writeIPSetToFile(warningIPSet, "warningIPSet.txt");
							logger.warn("IP pair " + ipPair + " added to warning IP set");
							limitFlow(sw, ipv4_src, ipv4_dst);// apply rate limit using limit flow
						} else {
							maliciousIPSet.add(ipPair); // add to malicious IP set
							writeIPSetToFile(maliciousIPSet, "maliciousIPSet.txt");
							logger.warn("IP pair " + ipPair + " added to malicious IP set");
							dropFlow(sw); // drop using drop flow
						}
						//ipPairCounter.put(ipPair, 0); // reset count to 0
						putIPAddressPair(ipCountMap,ipPair,0);
					}
				}
				break;
			case MALICIOUS_TO_DROP:
				if (containsIPAddressPair(maliciousIPSet,ipPair)) {
					System.out.println("模式： MALICIOUS_TO_DROP");
					dropFlow(sw); // drop using drop flow
				}
				break;
			default:
				break;
		}
		// write IP sets to log files
	}


	//具体限速实施细节
	//限定在ratelimit
	//
	public static void limitMeter(IOFSwitch sw, Long rateLimit) {
		MeterId++;
		logger.info("enter add limitmeter()");
		//设置OpenFlow版本
		OFFactory my13Factory = OFFactories.getFactory(OFVersion.OF_13);
		//设置flag
		Set<OFMeterFlags> flags = new HashSet<OFMeterFlags>();
		flags.add(OFMeterFlags.KBPS);

		//创建一个band
		OFMeterBandDrop bandDrop = my13Factory.meterBands().buildDrop()
				.setRate(rateLimit)    // kbps
				.build();

		logger.info("create band");

		//设置bands
		List<OFMeterBand> bands = new ArrayList<OFMeterBand>();
		bands.add(0, bandDrop);
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

	//在预警数据流中的地址进行限速
	//流表项添加
	public static void limitFlow(IOFSwitch sw, IPv4Address IPv4_SRC, IPv4Address IPv4_DST) {
		// 为指定地址添加限速
		limitMeter(sw, rateLimit);

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
		if (sw.write(fmb2.build())) {
			logger.info("add limitflow entry success");
		} else {
			logger.info("add limitflow entry failed");
		}
	}

	//正常情况下，默认转发
	public static void defaultFlow(IOFSwitch sw, IPv4Address IPv4_DST) {
		OFFlowMod.Builder fmb = sw.getOFFactory().buildFlowAdd();
		//匹配域
		Match.Builder mb = sw.getOFFactory().buildMatch();
		mb.setExact(MatchField.ETH_TYPE, EthType.IPv4)
				.setExact(MatchField.IPV4_DST, IPv4_DST);

		//指令与动作
		OFFactory myOF13Factory = OFFactories.getFactory(OFVersion.OF_13);
		List<OFAction> actions = new ArrayList<OFAction>();
		List<OFInstruction> instructions = new ArrayList<OFInstruction>();

		OFInstructionMeter meter = myOF13Factory.instructions().buildMeter()
				.setMeterId(MeterId)
				.build();

		OFAction output = myOF13Factory.actions().buildOutput()
				//对于.setPort(OFPort.of(2))，是从2端口转出去，但实际要根据topo情况不同而改变
				//controller是交给控制器处理
				.setPort(OFPort.CONTROLLER)
				.build();
		actions.add(output);
		instructions.add((OFInstruction) myOF13Factory.instructions().applyActions(actions));

		//流表项
		fmb.setHardTimeout(0)
				.setIdleTimeout(0)
				.setPriority(5)
				.setMatch(mb.build());
		fmb.setInstructions(instructions);

		if (sw.write(fmb.build())) {
			logger.info("add defaultFlow entry success");
		} else {
			logger.info("add defaultFlow entry failed");
		}
	}

	//在恶意数据流中的地址直接丢弃
	public static void dropFlow(IOFSwitch sw) {
		OFFactory ofFactory = sw.getOFFactory();
		Match match = ofFactory.buildMatch()
				.setExact(MatchField.ETH_TYPE, EthType.IPv4)
				.setExact(MatchField.IP_PROTO, IpProtocol.UDP)
				//.setExact(MatchField.UDP_DST, TransportPort.of(8080))
				.build();
		OFFlowAdd flowDelete = ofFactory.buildFlowAdd()
				.setPriority(5)
				.setIdleTimeout(0)
				.setHardTimeout(0)
				//.setOutPort(OFPort.of(1))
				.setMatch(match)
				.build();
		staticEntryPusherService.addFlow("flow" + packetCount, flowDelete, sw.getId());
		System.out.println("Drop rule installed on switch " + sw.getId());
		//staticEntryPusherService.addFlow("flow" + packetCount, flowAdd, sw.getId());
	}
}