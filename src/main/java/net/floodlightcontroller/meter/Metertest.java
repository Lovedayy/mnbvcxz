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
	private static Map<IPAddressPair, Integer> ipCountMap = new HashMap<>();//用于记录IP地址对出现次数的Map
	private Set<IPAddressPair> maliciousIPSet = new HashSet<>(); // 存储恶意IP地址对的集合
	private Set<IPAddressPair> historyIPSet = new HashSet<>(); // 存储历史IP地址对的集合
	private Set<IPAddressPair> warningIPSet = new HashSet<>(); // 存储预警IP地址对的集合


	private Map<IPAddressPair, Integer> ipPairCounter = new HashMap<>(); //统计每个 IP 地址对出现的次数

	public static final int NORMAL_TO_HISTORY = 0; // normal状态下的流表项ID，用于将IP地址对从normal状态转变为history状态
	public static final int NORMAL_TO_DEFAULT = 1; // normal状态下的流表项ID，用于将IP地址对从normal状态转变为default状态
	public static final int WARNING_TO_LIMIT = 2; // defence状态下的流表项ID，用于将IP地址对从warning状态转变为limit状态
	public static final int MALICIOUS_TO_DROP = 3; // defence状态下的流表项ID，用于将IP地址对从defence状态转变为drop状态

	// Parameters
	private static final int attackThreshold = 140;     // IP对出现次数的攻击阈值
	private static final int normalThreshold = 120;     // IP对出现次数的正常阈值
	private static final int attack = 10000;       // 流量阈值，单位kbit/s
	private static final int Period = 2;                    // 链路流量检测线程的执行周期
	private static final int timeThreshold = 5000;         // Edge port traffic check interval in milliseconds
	private static long MeterId = 0;              //计量表号，下发计量表时，初值需设为1
	private static final long rateLimit = 5000;                  //计量表限速后的速率
	//private static final int TRAFFIC_THRESHOLD = attackThreshold / 1000; // Edge port traffic rate threshold in kbit/s
	private static final int CONSECUTIVE_COUNT_THRESHOLD = 10; // Number of consecutive checks before changing system status back to NORMAL

	// System status variables 0=normal,1=defence
	private int status= 0;

	private static final int COUNTER_THRESHOLD = 10;  // 计数器的阈值
	private int packetCount = 0;  // 统计接收的数据包数目

	private long lastUpdateTime = 0;



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
					String srcIp = ipv4.getSourceAddress().toString();
					String dstIp = ipv4.getDestinationAddress().toString();

					IPv4Address srcIP = IPv4Address.of(srcIp);
					IPv4Address dstIP = IPv4Address.of(dstIp);
					IPAddressPair ipPair = new IPAddressPair(srcIP, dstIP);

					logger.info("IPv4: Source IPv4 address:" + ipv4.getSourceAddress() + ",destination IPv4 address:" + ipv4.getDestinationAddress());

					// 判断ipCountMap中是否已经存在了当前的ipPair，如果存在则将对应的计数加1，否则将计数设为1
					int count = ipCountMap.containsKey(ipPair) ? ipCountMap.get(ipPair) + 1 : 1;
					ipCountMap.put(ipPair, count);
					classifyFlow(ipPair, count);
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

	//获取边缘交换机
	//得到边缘端口的接收速率和发送速率
	//计算出现次数
	//
	@Override
	public void getSwitchPorts() {
			Set<DatapathId> swid = new HashSet<DatapathId>(ofswitch.getAllSwitchDpids());
			Set<SwitchPort> switchports = new HashSet<SwitchPort>();

			for (DatapathId dpid : swid) {
				Set<OFPort> ports = new HashSet<OFPort>(topology.getPorts(dpid));
				for (OFPort port : ports) {
					if (topology.isEdge(dpid, port)) {
						SwitchPort switchPort = new SwitchPort(dpid, port);
						switchports.add(switchPort);

						// 获取端口的发送流量速率和接收流量速率
						SwitchPortBandwidth data = statistics.getBandwidthConsumption((DatapathId) swid, port);
						if (data != null) {
							long rxRate = data.getBitsPerSecondRx().getValue() / 1000;
							long txRate = data.getBitsPerSecondTx().getValue() / 1000;

							// 判断流量是否超过阈值
							if (rxRate > attack && txRate > attack) {
								packetCount++;
					}
				}
			}
		}
	}
		long currentTime = System.currentTimeMillis();
		long elapsedTime = currentTime - lastUpdateTime;
		// 根据超过阈值的端口数量和时间来更新系统状态
		if (elapsedTime > timeThreshold) {
			if (packetCount > 0) {
				if (status == 0) {
					// 如果系统之前处于正常状态，则记录当前时间，并将系统状态设置为防御状态
					status = 1;
				} else if (status == 1 && (currentTime - lastUpdateTime) > 10 * timeThreshold) {
					// 如果系统之前已经处于防御状态，并且连续10个时间间隔内都没有超过流量阈值，则将系统状态设置为正常状态
					status = 0;
				}
			} else {
				// 如果没有端口的流量超过阈值，则将系统状态设置为正常状态
				status = 0;
			}
			logger.info("Current system status: " + status);
			lastUpdateTime = currentTime;
		}
		// 将获取到的端口列表保存到成员变量中
		this.switchports = switchports;
	}

	@Override
	public void getPortFlows() {

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
	public void classifyFlow(IPAddressPair ipPair, int count) {
		switch (status) {
			//normal
			case 0:
				if (count > normalThreshold && !maliciousIPSet.contains(ipPair)) {
					addFlow(ipPair, NORMAL_TO_HISTORY);
				} else {
					addFlow(ipPair, NORMAL_TO_DEFAULT);
				}
				break;

			//defence
			case 1:
				if (count > attackThreshold) {
					if (historyIPSet.contains(ipPair)) {
						addFlow(ipPair, WARNING_TO_LIMIT);
					} else {
						addFlow(ipPair, MALICIOUS_TO_DROP);
						maliciousIPSet.add(ipPair);
					}
				} else {
					addFlow(ipPair, NORMAL_TO_DEFAULT);
				}
				break;

			default:
				addFlow(ipPair, NORMAL_TO_DEFAULT);
				break;
		}
	}

	private void addFlow(IPAddressPair ipPair, int flowType) {
		IOFSwitch sw = switchService.getActiveSwitch(DatapathId.of(ipPair.getSrcIP().getInt())); // get the source switch
		IPv4Address ipv4_src = ipPair.getSrcIP(); // get the source IP address
		IPv4Address ipv4_dst = ipPair.getDstIP(); // get the destination IP address

		switch (flowType) {
			case NORMAL_TO_HISTORY:
				// add flow to move packets from normal table to history table
				// e.g. staticEntryPusherService.addFlow(switch, inputPort, ipPair, NORMAL_TO_HISTORY);
				if (ipPairCounter.containsKey(ipPair)) {
					int count = ipPairCounter.get(ipPair);
					if (count > normalThreshold && !maliciousIPSet.contains(ipPair)) {
						ipPairCounter.put(ipPair, 0); // reset count to 0
						historyIPSet.add(ipPair); // add to history IP set
						logger.info("IP pair " + ipPair + " added to history IP set");
					}
				}
				break;

			case NORMAL_TO_DEFAULT:
				if (ipPairCounter.containsKey(ipPair)) {
					int count = ipPairCounter.get(ipPair);
					if (count <= normalThreshold || maliciousIPSet.contains(ipPair)) {
						ipPairCounter.put(ipPair, 0); // reset count to 0
						defaultFlow(sw, ipv4_dst); // forward using default flow
					}
				}
				break;

			case WARNING_TO_LIMIT:
				// add flow to move packets from warning table to limit table
				// e.g. staticEntryPusherService.addFlow(switch, inputPort, ipPair, WARNING_TO_LIMIT);
				if (ipPairCounter.containsKey(ipPair)) {
					int count = ipPairCounter.get(ipPair);
					if (count > attackThreshold) {
						if (historyIPSet.contains(ipPair)) {
							warningIPSet.add(ipPair); // add to warning IP set
							logger.warn("IP pair " + ipPair + " added to warning IP set");
							limitFlow(sw, ipv4_src, ipv4_dst);// apply rate limit using limit flow
						} else {
							maliciousIPSet.add(ipPair); // add to malicious IP set
							logger.warn("IP pair " + ipPair + " added to malicious IP set");
							dropFlow(sw, ipv4_src, ipv4_dst); // drop using drop flow
						}
						ipPairCounter.put(ipPair, 0); // reset count to 0
					}
				}
				break;
			case MALICIOUS_TO_DROP:
				// add flow to drop packets from malicious IP pair
				// e.g. staticEntryPusherService.addDropFlow(switch, inputPort, ipPair);
				if (maliciousIPSet.contains(ipPair)) {
					dropFlow(sw, ipv4_src, ipv4_dst); // drop using drop flow
				}
				break;
			default:
				break;
		}
		// write IP sets to log files
		writeIPSetToFile(historyIPSet, "historyIPSet.txt");
		writeIPSetToFile(warningIPSet, "warningIPSet.txt");
		writeIPSetToFile(maliciousIPSet, "maliciousIPSet.txt");
	}


	//具体限速实施细节
	//限定在ratelimit
	//
	public static void limitMeter(IOFSwitch sw, Long rateLimit){
		MeterId++;
		logger.info("enter add limitmeter()");
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

	//在预警数据流中的地址进行限速
	//流表项添加
	public static void limitFlow(IOFSwitch sw, IPv4Address IPv4_SRC, IPv4Address IPv4_DST)
	{
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
		if(sw.write(fmb2.build())) {
			logger.info("add limitflow entry success");
		}
		else {
			logger.info("add limitflow entry failed");
		}
	}

	//正常情况下，默认转发
	public static void defaultFlow(IOFSwitch sw, IPv4Address IPv4_DST){
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
		instructions.add((OFInstruction) myOF13Factory.instructions().applyActions(actions)) ;

        //流表项
        fmb.setHardTimeout(0)
				.setIdleTimeout(0)
                .setPriority(5)
                .setMatch(mb.build());
        fmb.setInstructions(instructions);
       
        if(sw.write(fmb.build())) {
              logger.info("add defaultFlow entry success");
          }
          else {
              logger.info("add defaultFlow entry failed");
          }
	}

	//在恶意数据流中的地址直接丢弃
	public static void dropFlow(IOFSwitch sw, IPv4Address IPv4_SRC, IPv4Address IPv4_DST)
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

		OFAction output = myOF13Factory1.actions().buildOutput().build();
		actions.add(output);

		instructions.add((OFInstruction) myOF13Factory1.instructions().applyActions(actions)) ;

		//流表项
		fmb1.setHardTimeout(0)
				.setIdleTimeout(0)
				.setPriority(5)
				.setMatch(mb1.build());
		fmb1.setInstructions(instructions);

		if(sw.write(fmb1.build())) {
			logger.info("dd dropFlow success");
		}
		else {
			logger.info("MM:add dropFlow failed");
		}
	}
}