package net.floodlightcontroller.savi.module;

import io.netty.util.internal.ConcurrentSet;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.core.util.SingletonTask;
import net.floodlightcontroller.devicemanager.SwitchPort;
import net.floodlightcontroller.packet.DHCPv6Option;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.ICMPv6Option;
import net.floodlightcontroller.routing.IRoutingDecision.RoutingAction;
import net.floodlightcontroller.savi.action.*;
import net.floodlightcontroller.savi.binding.Binding;
import net.floodlightcontroller.savi.service.SAVIProviderService;
import net.floodlightcontroller.savi.service.SAVIService;
import net.floodlightcontroller.threadpool.IThreadPoolService;
import net.floodlightcontroller.topology.ITopologyService;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.IPv6Address;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * SAVI base service, new module should extends SAVIBaseService. 
 * @author zhouyu
 *
 */
public abstract class SAVIBaseService implements SAVIService, IFloodlightModule{

	static Logger log = LoggerFactory.getLogger(SAVIBaseService.class);
	// Dependent services
	IFloodlightProviderService floodlightProvider;
	IThreadPoolService threadPoolService;
	SAVIProviderService	saviProvider;
	SingletonTask deadlineTimer;
//	ITopologyService topologyService;
    IOFSwitchService switchService;
    //DAD检测容器
    List<Binding<IPv6Address>> dadContainer;
    //防止出错 主机可能已经绑定好了本地链路地址 控制器还未绑定	todo 进一步就是已经配置了两个公网地址，但是没检测出来的情况 <概率较低暂不考虑>
	Set<SwitchPort> formerHost;
    Map<SwitchPort, List<ICMPv6Option>> prefixInfo;   //slaac集合 包含前缀
	Set<SwitchPort> dhcpInfo;   //dhcpv6集合
	Map<SwitchPort, List<Binding<IPv6Address>>> bindingMap;
	Map<SwitchPort, Integer> globalIPNum;
	Map<SwitchPort, Binding<IPv6Address>> replyQueue;
	Binding<IPv6Address> srcBind=new Binding<>();
	//DHCPv6服务器端口
	Set<SwitchPort> dhcpPorts;

	File file;
	BufferedWriter bw;

	@Override
	public void pushActins(List<Action> actions) {
		// TODO Auto-generated method stub
		for(Action action:actions) {
			switch(action.getType()){
			case CLEAR_IPv4_BINDING:
				doClearIPv4BindingAction((ClearIPv4BindingAction)action);
				break;
			case CLEAR_IPv6_BINDING:
				doClearIPv6BindingAction((ClearIPv6BindingAction)action);
				break;
			case CLEAR_PORT_BINDING:
				doClearPortBindingAction((ClearPortBindingAction)action);
				break;
			case CLEAR_SWITCH_BINDING:
				doClearSwitchBindingAction((ClearSwitchBindingAction)action);
				break;
			case CLEAR_MAC_BINDING:
				doClearMacBindingAction((ClearMacBindingAction)action);
				break;
			default:
				break;
			}
		}
	}

	protected void doClearIPv4BindingAction(ClearIPv4BindingAction action){
		
	}
	
	protected void doClearIPv6BindingAction(ClearIPv6BindingAction action){
		
	}
	
	protected void doClearPortBindingAction(ClearPortBindingAction action){
		
	}
	
	protected void doClearSwitchBindingAction(ClearSwitchBindingAction action){
		
	}
	
	protected void doClearMacBindingAction(ClearMacBindingAction action){
		
	}
	
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		// TODO Auto-generated method stub
		Collection<Class<? extends IFloodlightService>> dependencies = new ArrayList<Class<? extends IFloodlightService>>();
		dependencies.add(IFloodlightProviderService.class);
		dependencies.add(IThreadPoolService.class);
		dependencies.add(SAVIProviderService.class);
		dependencies.add(ITopologyService.class);
		dependencies.add(IOFSwitchService.class);
		return dependencies;
	}

	@Override
	public void init(FloodlightModuleContext context) throws FloodlightModuleException {
		floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
		threadPoolService =context.getServiceImpl(IThreadPoolService.class);
		saviProvider	= context.getServiceImpl(SAVIProviderService.class);
//		topologyService = context.getServiceImpl(ITopologyService.class);
		switchService = context.getServiceImpl(IOFSwitchService.class);
		
		dadContainer = new CopyOnWriteArrayList<>();
		formerHost = new HashSet<>();
        prefixInfo = new ConcurrentHashMap<>();
        dhcpInfo = new ConcurrentSet<>();
        bindingMap = new ConcurrentHashMap<>();
        globalIPNum=new ConcurrentHashMap<>();
        replyQueue=new ConcurrentHashMap<>();
        dhcpPorts=new HashSet<>();
		//控制器ip
		final IPv6Address CONTROLLER_IP=IPv6Address.of("fe80::6851:4d1a:5bab:b33f");
		//控制器mac
		final MacAddress CONTROLLER_MAC=MacAddress.of("00:50:56:c0:00:08");
		srcBind.setMacAddress(CONTROLLER_MAC);
		srcBind.setAddress(CONTROLLER_IP);

		initIO();
	}

	void initIO(){
		file=new File(("D:/savilog/slaacLefttime.txt"));
//		file=new File(("D:/savilog/dhcpLefttime.txt"));
		if (!file.exists()) {
			try {
				file.createNewFile();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}

		try {
			bw=new BufferedWriter(new OutputStreamWriter(new FileOutputStream(file, false)));
		} catch (FileNotFoundException e) {
			try {
				if(bw!=null)
					bw.close();
			} catch (IOException e1) {
				e1.printStackTrace();
			}
			e.printStackTrace();
		}
	}
	void writeToTxt(long diff){
		System.out.println("######Left time: "+diff+"######");
		try {
			bw.write(Long.toString(diff));
			bw.newLine();
			bw.flush();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	@Override
	public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
		// TODO Auto-generated method stub
		saviProvider.addSAVIService(this);
		
		ScheduledExecutorService ses = threadPoolService.getScheduledExecutor();
		
		deadlineTimer = new SingletonTask(ses, new Runnable() {
			
			@Override
			public void run() {
				// TODO Auto-generated method stub
				checkDeadline();
				deadlineTimer.reschedule(1, TimeUnit.SECONDS);
			}
		});
		deadlineTimer.reschedule(1, TimeUnit.SECONDS);
		SwitchPort switchPort=new SwitchPort(DatapathId.of(1), OFPort.of(1));
		dhcpPorts.add(switchPort);

		startUpService();
	}

	@Override
	public abstract boolean match(Ethernet eth);
	
	@Override
	public abstract List<Match> getMatches() ;
	
	@Override
	public abstract RoutingAction process(SwitchPort switchPort, Ethernet eth) ;
	
	public abstract void checkDeadline();
	
	public abstract void startUpService();

}
