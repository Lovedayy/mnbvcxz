package net.floodlightcontroller.meter;

import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.OFPort;

import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.statistics.SwitchPortBandwidth;

public interface IMetertestService extends IFloodlightService{
	
	
	//获取交换机id和该交换机与主机相连的交换机端口
	public void getSwitchPorts();
	
	//获取端口速率
	public void getPortFlows();
	

}
