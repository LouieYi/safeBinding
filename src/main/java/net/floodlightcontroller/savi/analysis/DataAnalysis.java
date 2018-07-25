package net.floodlightcontroller.savi.analysis;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.lang.Thread.State;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.text.DecimalFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

import org.projectfloodlight.openflow.protocol.OFFactories;
import org.projectfloodlight.openflow.protocol.OFFlowStatsEntry;
import org.projectfloodlight.openflow.protocol.OFFlowStatsReply;
import org.projectfloodlight.openflow.protocol.OFPortStatsEntry;
import org.projectfloodlight.openflow.protocol.OFPortStatsReply;
import org.projectfloodlight.openflow.protocol.OFStatsReply;
import org.projectfloodlight.openflow.protocol.OFStatsRequest;
import org.projectfloodlight.openflow.protocol.OFStatsType;
import org.projectfloodlight.openflow.protocol.OFVersion;
import org.projectfloodlight.openflow.protocol.instruction.OFInstruction;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.protocol.ver13.OFMeterSerializerVer13;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv6Address;
import org.projectfloodlight.openflow.types.OFGroup;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.TableId;
import org.projectfloodlight.openflow.types.U64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.primitives.UnsignedLong;
import com.google.common.util.concurrent.ListenableFuture;

import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.core.util.SingletonTask;
import net.floodlightcontroller.devicemanager.SwitchPort;
import net.floodlightcontroller.restserver.IRestApiService;
import net.floodlightcontroller.savi.analysis.web.AnalysisWebRoutable;
import net.floodlightcontroller.savi.binding.Binding;
import net.floodlightcontroller.savi.flow.FlowAction;
import net.floodlightcontroller.savi.flow.FlowAction.FlowActionFactory;
import net.floodlightcontroller.savi.service.SAVIProviderService;
import net.floodlightcontroller.threadpool.IThreadPoolService;

public class DataAnalysis implements IFloodlightModule, IAnalysisService {

	private static final Logger log=LoggerFactory.getLogger(DataAnalysis.class);
	
	//需要用到的Service
	private static IThreadPoolService threadPoolService;
	private static IOFSwitchService switchService;
	private static IRestApiService restApiService;
	private static SAVIProviderService saviProvider;
	
	//定时器，在startUp里面调用其他方法，启动核心功能
	private static ScheduledFuture<?> flowSchedule;
	private static ScheduledFuture<?> portPackets;
	private static int flowStasInterval = 1;
	
	//该字段控制模块是否启用，注意enable是key
	public static boolean isEnable= false;
	private static final String ENABLED_STR = "enable";
	//该字段控制正常、异常等工作模式
	public static boolean isSecurity = true;
	private static final String SECURE_STR = "secure";
	//该字段用来控制方案类型，它的值可以修改为后面几个，默认采用丢包
	public static int STATUS = 1;
	//以下字段是代表决策方案，0表示初始阶段，1表示采用丢包率的方案
	public static final int INIT_STAGE = 0;
	public static final int PLAN_LOSSRATE = 1;
	public static final int PLAN_TRAFFIC = 2;
	public static final int RELIABLE_PORT_PRIORITY = 200;
	//绑定优先级，5较高，4较低
	static final int BINDING_PRIORITY = 5;

	//linux下用这个目录
	//private static String filePath = "/home/sdn/savi/log/maxtraffic.txt";
	//private static String filePath2 = "/home/sdn/savi/log/";
//	private static String filePath3 = "/home/sdn/savi/log/rulenum.txt";
//	private static String filePath4 = "/home/sdn/savi/log/singlenum.txt";
	
	//保存历史峰值的文件
	private static String filePath = "E:/maxtraffic.txt";
	//累计历史流量
	private static String filePath2 = "E:/savilog/";
	private static String filePath5 ="E:/savilog/abnormalLog.txt";
//	private static String filePath3 = "E:/savilog/rulenum.txt";
//	private static String filePath4 = "E:/savilog/singlenum.txt";
	
	//接下来这段map，在PortStatsCollector中统计端口流量
	private static final Map<SwitchPort, U64> inPortPackets = new ConcurrentHashMap<SwitchPort, U64>();
	private static final Map<SwitchPort, U64> inTentativePortPackets = new ConcurrentHashMap<SwitchPort, U64>();
	private static final Map<SwitchPort, U64> inPortPacketsRes = new ConcurrentHashMap<SwitchPort, U64>();
	private static final Map<SwitchPort, U64> outPortPackets = new ConcurrentHashMap<SwitchPort, U64>();
	private static final Map<SwitchPort, U64> outTentativePortPackets = new ConcurrentHashMap<SwitchPort, U64>();
	private static final Map<SwitchPort, U64> outPortPacketsRes = new ConcurrentHashMap<SwitchPort, U64>();
	//计算丢包率的map，在FlowStatsCollector用到
	private static final Map<SwitchPort , PacketOfFlow> packetOfFlows = new ConcurrentHashMap<>();
	//保存数据流量历史峰值的map
	private static final Map<Integer, Double> maxTraffics = new ConcurrentHashMap<>();
	//每个端口对应的同一个交换机的其他端口出流量的总和，用来衡量是否为异常流量
	private static final Map<Integer, Double> outTraffics = new ConcurrentHashMap<>();
	
	//第一阶段用来延迟执行的定时器，在需要用到的地方配合ScheduledExecutorService来new一个即可
	private SingletonTask initTimer;
	//使用静态规则的交换机 丢包率检测
//	private SingletonTask staticLossRate;
	
	private double LOSS_RATE_THRESHOLD = 0.2;
	private int LOSS_NUM_THRESHOLD = 100;
	
	//分别表示正常端口队列、异常端口队列
	private Queue<SwitchPort> normalPorts = new ConcurrentLinkedQueue<>();
	private Set<SwitchPort> pickFromNormal = new HashSet<>();
	private Queue<SwitchPort> abnormalPorts = new ConcurrentLinkedQueue<>();
	private Map<SwitchPort, Integer> observePorts = new ConcurrentHashMap<>();
	//上一轮的正常端口
	private Set<SwitchPort> rightPorts = new HashSet<>();
	
//	private Set<SwitchPort> handleSet	= new HashSet<>();
	
	@SuppressWarnings("all")
	private static ScheduledFuture<?> normalPortSchedule;
	@SuppressWarnings("all")
	private static ScheduledFuture<?> abnormalPortSchedule;
	@SuppressWarnings("all")
	private static ScheduledFuture<?> observePortSchedule;
	
	//正常队列每次选取的端口数
	private static int normalNum = 3;
	//定义观察次数，超过3次正常才放回正常队列
//	private static int observeCount = 3;
	
	//测试用的定时器timer
	private SingletonTask testTimer;
	private SingletonTask timer2;
	//写累积历史数据的timer
	private SingletonTask flowlogTimer;
	private SingletonTask checkRules;
	
	//定义tableId
	private static TableId STATIC_TABLE_ID=TableId.of(0);
	private static TableId DYNAMIC_TABLE_ID=TableId.of(1);
	private static TableId FLOW_TABLE_ID = TableId.of(2);
	
	//交换机流量大小排名 即端口排名
	private Map<SwitchPort, Integer> rank;
	//每个交换机异常端口的数量
	private Map<DatapathId, Integer> abnormalPortsNum	=new HashMap<>();
	//每个交换机在绑定表里的端口数
	private Map<DatapathId, Integer> portsInBind;
	//用于判断是否需要静态和动态转换
//	private Map<DatapathId, Boolean> convertFlag		=new HashMap<>();
	//修改优先级的时间周期
	private short cycleTime=5;
	private short period=20;
	//周期内端口的包数
	private Map<SwitchPort, U64> packetsInPeriod	= new HashMap<>();
	//记录上一次收到的包数
	private Map<SwitchPort, U64> packetsInRecord	=new HashMap<>();
	//用于标记何时开始记录已收到的包数
	private boolean timeToSave=true;
	//用于记录当前的交换机下的绑定端口
	private Set<SwitchPort> portsList				=new HashSet<>();
	//priority level
	private int priorityLevel=96;
	private Set<DatapathId> staticSwId;
	//fix bug
	private long stableTime	;
	//主机信用等级
	private Map<SwitchPort, Integer> hostsCredit		=new HashMap<>();
	private boolean synAutoCheck		=true;
	//log flag
	private Map<SwitchPort, Boolean> logFlag=		new HashMap<>();
	
//	private Map<DatapathId, Integer> timeToMatch	=new HashMap<>();
	
	private SimpleDateFormat sdflog = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
	
	//由于提供了服务，完善相关方法
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		Collection<Class<? extends IFloodlightService>> services=new ArrayList<Class<? extends IFloodlightService>>();
		services.add(IAnalysisService.class);
		return services;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		Map<Class<? extends IFloodlightService>, IFloodlightService> map=new HashMap<Class<? extends IFloodlightService>, IFloodlightService>();
		map.put(IAnalysisService.class, this);
		return map;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l=new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IThreadPoolService.class);
		l.add(IOFSwitchService.class);
		l.add(IRestApiService.class);
		l.add(SAVIProviderService.class);
		return l;
	}

	@Override
	public void init(FloodlightModuleContext context) throws FloodlightModuleException {
		//初始化需要用到的服务 
		switchService=context.getServiceImpl(IOFSwitchService.class);
		threadPoolService=context.getServiceImpl(IThreadPoolService.class);
		restApiService=context.getServiceImpl(IRestApiService.class);
		saviProvider=context.getServiceImpl(SAVIProviderService.class);
		
		rank=			/*Provider.rank;*/						saviProvider.getRank();
		portsInBind=	/*Provider.portsInBind;*/				saviProvider.getPortsInBind();
		staticSwId=		/*Provider.staticSwId;*/				saviProvider.getStaticSwId();
//		normalPorts=	/*Provider.normalPorts;*/				saviProvider.getNormalPorts();
//		abnormalPorts=	/*Provider.abnormalPorts;*/				saviProvider.getAbnormalPorts();
//		observePorts=	/*Provider.observePorts;*/				saviProvider.getObservePorts();
		
		//对配置文件参数进行解析
		Map<String, String> config = context.getConfigParams(this);
		
		if(config.containsKey(ENABLED_STR)){
			try {
				isEnable = Boolean.parseBoolean(config.get(ENABLED_STR).trim());
			} catch (Exception e) {
				log.error("Could not parse '{}'. Using default of {}", ENABLED_STR, isEnable);
			}
		}
		if(config.containsKey(SECURE_STR)){
			try {
				isSecurity = Boolean.parseBoolean(config.get(SECURE_STR).trim());
			} catch (Exception e) {
				log.error("Could not parse '{}'. Using default of {}", SECURE_STR, isSecurity);
			}
		}
	}

	@Override
	public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
		//启动rest api
		restApiService.addRestletRoutable(new AnalysisWebRoutable());
		
		firstStage();
		//下面在系统运行期间输出调试信息
		ScheduledExecutorService ses1 = threadPoolService.getScheduledExecutor();
		testTimer = new SingletonTask(ses1, new Runnable() {
			
			@Override
			public void run() {
				//每隔0.5秒获取一次三个队列的元素
				StringBuffer sb = new StringBuffer();
				testPortSet(sb, normalPorts, "normal");
				testPortSet(sb, observePorts.keySet(), "observe");
				testPortSet(sb, abnormalPorts, "abnormal");
				log.info(sb.toString());
				testTimer.reschedule(500, TimeUnit.MILLISECONDS);
			}
		});
		//testTimer.reschedule(90, TimeUnit.SECONDS);
		testTimer.reschedule(40, TimeUnit.SECONDS);
		
		ScheduledExecutorService ses2 = threadPoolService.getScheduledExecutor();
		timer2 = new SingletonTask(ses2, new Runnable() {
			
			@Override
			public void run() {
				//如果采用定时器，那么这里就变成实时刷新了
//				if(STATUS == PLAN_TRAFFIC){
//					//得到稳定的出流量集合（只有背景流量），并且获得后暂时无法修改
//					updateOutFlow();
//				}
				updateOutFlow();
				//showOutFlow();
				//timer2.reschedule(6, TimeUnit.SECONDS);
				//不用定时器，那么只会执行一次，系统默认采用丢包率的方案，因此不能用上面的if
				
			}
		});
		//这个地方不是定时器，而是延迟执行，因为timer2里面没有设置下一次重启时间。
		timer2.reschedule(45, TimeUnit.SECONDS);
		
		//该定时器专门用来写累积历史数据文件，这里只记录in流量，out流量或specifyOut流量暂时不管，一个定时器写多个文件情况未知。
		ScheduledExecutorService ses3 = threadPoolService.getScheduledExecutor();
		flowlogTimer = new SingletonTask(ses3, new Runnable() {
			
			@Override
			public void run() {
				StringBuffer sb = new StringBuffer();
				
				double[] tempV = new double[rank.size() + 1];
				
				for(SwitchPort swport : rank.keySet()){
					if(swport.getPort().getPortNumber()>0){
						U64 u=inPortPacketsRes.get(swport)==null?U64.ZERO:inPortPacketsRes.get(swport);
						//将端口转主机编号，因为文件里面读取出来的就是主机编号
						//用该数字作为数组下标
						int terminatorNum = computeTerminatorNum(swport);
						if(terminatorNum==-1) continue;
						//计算当前速率
						double v = u.getValue()/(1.0 * flowStasInterval);
						tempV[terminatorNum] = v;
					}
				}
				//填充tempV数组后，1-9号主机的入流量就是下标对应的值
				
				//分割系统时间，splits[0]为日期，1为时刻
				String[] splits =  sdflog.format(System.currentTimeMillis()).split(" ");
				
				//文件第一列为时刻
				sb.append(splits[1] + " ");
				for(int i = 1; i < tempV.length; i++){
					sb.append(tempV[i]);
					if(i != tempV.length-1){
						sb.append(",");
					}
				}
				sb.append("\r\n");
				//日期作为文件名
				writeToTxt(filePath2 + splits[0] +".txt", true, sb.toString());
				
				flowlogTimer.reschedule(flowStasInterval*2, TimeUnit.SECONDS);
			}
		});
		//40s后保证数据收集线程已经开启，因为需要用到inPortsPacketsRes
		flowlogTimer.reschedule(50, TimeUnit.SECONDS);
		
		ScheduledExecutorService ses4 = threadPoolService.getScheduledExecutor();
		checkRules= new SingletonTask(ses4, new Runnable() {
			
			@Override
			public void run() {
				for(DatapathId dpid : staticSwId) {
					convertTable(dpid, false);
				}
				checkRules.reschedule(20, TimeUnit.SECONDS);
			}
		});
//		try {
//			checkRules.wait();
//		} catch (InterruptedException e) {
//			e.printStackTrace();
//		}
		checkRules.reschedule(60, TimeUnit.SECONDS);
	}

	//2018.4.7之前，经测试，这个方法的累加结果和getOutPacketsByPort一致，可以用来统计出流量并实时刷新了
	//该方法可用于显示实时的outFlow，但并不是outTraffic的内容。
//	@Override
//	public Object showOutFlow() {
//		Map<Integer, Long> map = new HashMap<>();
//		for(int i = 1; i <= 9; i++){
//			map.put(i, 0L);
//		}
//		//统计所有出流量并输出
//		for(Map.Entry<SwitchPort, U64> entry : outPortPacketsRes.entrySet()){
//			SwitchPort sp = entry.getKey();
//			if(sp.getSwitchDPID().toString().contains("1")) continue;
//			//实际上用这个方法和下面的结果是一致的
////			if(sp.getPort().getPortNumber() != 4 && sp.getPort().getPortNumber() != -2){
////				System.out.println(((int)sp.getSwitchDPID().getLong() - 2) * 3 + sp.getPort().getPortNumber() + " " + getOutPacketsByPort(sp));
////			}
//			int prefix = ((int)sp.getSwitchDPID().getLong() - 2) * 3;
//			if(sp.getPort().getPortNumber() == 4){
//				//端口号为4，累加到1,2,3
//				map.put(prefix + 1, entry.getValue().getValue() + map.get(prefix + 1));
//				map.put(prefix + 2, entry.getValue().getValue() + map.get(prefix + 2));
//				map.put(prefix + 3, entry.getValue().getValue() + map.get(prefix + 3));
//			}
//			else if(sp.getPort().getPortNumber() == 1){
//				//当前端口号为1，就累加到2和3
//				map.put(prefix + 2, entry.getValue().getValue() + map.get(prefix + 2));
//				map.put(prefix + 3, entry.getValue().getValue() + map.get(prefix + 3));
//			}
//			else if(sp.getPort().getPortNumber() == 2){
//				map.put(prefix + 1, entry.getValue().getValue() + map.get(prefix + 1));
//				map.put(prefix + 3, entry.getValue().getValue() + map.get(prefix + 3));
//			}
//			else if(sp.getPort().getPortNumber() == 3){
//				map.put(prefix + 1, entry.getValue().getValue() + map.get(prefix + 1));
//				map.put(prefix + 2, entry.getValue().getValue() + map.get(prefix + 2));
//			}
//		}
//		StringBuffer sb = new StringBuffer();
//		DecimalFormat df = new DecimalFormat("####0.00");
//		for(Map.Entry<Integer, Long> entry : map.entrySet()){
//			sb.append(entry.getKey() + " " + df.format(entry.getValue()/(2.0 * flowStasInterval)) + "\r\n");
//		}
//		log.info("当前出口流量集合如下：\r\n" + sb.toString() + "====================");
//		return map;
//	}
	

	//2018.4.8 该方法的应该是从实时更新的数值中找到背景流量的稳定值（放到outTraffic中），大流量的情况不应该更新到该值中
	//由于延时的关系，此时获取到的值，就当是稳定流量值了
	@Override
	public void updateOutFlow() {
		//统计所有出流量并输出
		for(Map.Entry<SwitchPort, U64> entry : outPortPacketsRes.entrySet()){
			SwitchPort sp = entry.getKey();
			if(rank.containsKey(sp)){
				double curOut = getOutPacketsByPort(sp)/(1.0 * flowStasInterval);
				outTraffics.put(computeTerminatorNum(sp),curOut);
			}
		}
		StringBuffer sb = new StringBuffer();
		DecimalFormat df = new DecimalFormat("####0.00");
		for(Map.Entry<Integer, Double> entry : outTraffics.entrySet()){
			sb.append(entry.getKey() + " " + df.format(entry.getValue()) + "\r\n");
		}
		log.info("当前出口流量集合如下：\r\n" + sb.toString() + "====================");
	}
	
	//REST API输出实时的出端口流量，但不是outTraffics集合中的
	public Object showOutFlow() {
		Map<Integer, Double> map = new HashMap<>();
		//统计所有出流量并输出
		for(Map.Entry<SwitchPort, U64> entry : outPortPacketsRes.entrySet()){
			SwitchPort sp = entry.getKey();
			if(sp.getSwitchDPID().toString().contains("1")) continue;
			if(rank.containsKey(sp)){
				map.put(computeTerminatorNum(sp), getOutPacketsByPort(sp)/(1.0 * flowStasInterval));
			}
		}
		StringBuffer sb = new StringBuffer();
		DecimalFormat df = new DecimalFormat("####0.00");
		for(Map.Entry<Integer, Double> entry : map.entrySet()){
			sb.append(entry.getKey() + " " + df.format(entry.getValue()) + "\r\n");
		}
		log.info("当前出口流量集合如下：\r\n" + sb.toString() + "====================");
		//由于返回的map的value仍然是double，因此在通过rest得到的值没有保留2位小数。
		return map;
	}
	
	//如果读文件失败，那么调用这个方法，不采用原来的默认填充全0，而是填充之前实验得到的固定值
	private void trafficToMap(){
		//这里默认填充的值都比文件中的值大一位小数
//		maxTraffics.put(1, 2.5);
//		maxTraffics.put(2, 143.7);
//		maxTraffics.put(3, 32.5);
//		maxTraffics.put(4, 103.4);
//		maxTraffics.put(5, 5.4);
//		maxTraffics.put(6, 117.2);
//		maxTraffics.put(7, 90.4);
//		maxTraffics.put(8, 2.4);
//		maxTraffics.put(9, 5.4);
		for(int i = 1; i <= rank.size(); i++){
			maxTraffics.put(i, 100.0);
		}
	}
	
	//读文件，将历史峰值填充到hashmap
	private void trafficToMap(String filename){
		try {
			synchronized (filename) {
				File file = new File(filename);
				if(!file.exists()){
					log.info("文件不存在");
					file.createNewFile();
					
					trafficToMap();
					return;
				}
				BufferedReader in = new BufferedReader(new FileReader(filename));
				try {
					String temp = null;
					boolean flag = false;
					while((temp = in.readLine()) != null){
						flag = true;
						String[] splits = temp.split(" ");
						//只要格式不对，直接返回
						if(splits.length != 2 || !isInteger(splits[0]) || !isDouble(splits[1])) {
							trafficToMap();
							return;
						}
						else {
							//这里容易发生异常
							maxTraffics.put(Integer.parseInt(splits[0]), Double.parseDouble(splits[1]));
						}
					}
					//说明是空文件
					if(!flag){
						trafficToMap();
					}
					else {
						for( Map.Entry<Integer, Double> entry : maxTraffics.entrySet()){
							System.out.println(entry.getKey() + " " + entry.getValue());
						}
					}
					in.close();
				} catch (Exception ex){
					//最可能发生的异常是数字转换的错误，或者文件读写错误
					ex.printStackTrace();
				}
				finally {
					if(in != null){
						try {
							in.close();
						}catch(IOException e){}
					}
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * 正则表达式判断是否是double类型，主要用于读文件
	 * @param str
	 * @return
	 */
	private boolean isDouble(String str) {
		if (null == str || "".equals(str)) {  
	        return false;  
	    }  
	    Pattern pattern = Pattern.compile("^[-\\+]?[.\\d]*$");  
	    return pattern.matcher(str).matches();  
	}

	/**
	 * 正则表达式判断是否是整数，主要用于读文件
	 * @param str
	 * @return
	 */
	private boolean isInteger(String str) {
		if (null == str || "".equals(str)) {  
	        return false;  
	    }  
	    Pattern pattern = Pattern.compile("^[-\\+]?[\\d]*$");  
	    return pattern.matcher(str).matches(); 
	}

	

	private void testPortSet(StringBuffer sb , Collection<SwitchPort> switchPorts, String name){
		if(sb == null) return ;
		sb.append(name + "[ ");
		for(SwitchPort sp : switchPorts){
			sb.append(computeTerminatorNum(sp) + ",");
		}
		sb.deleteCharAt(sb.length()-1);
		sb.append(" ]" + "  ");
	}
	
	//初始阶段
	private void firstStage(){
		//2.初始化一个定时器，20s后执行一次
		//将数据流量的历史峰值从文件读入系统，后面的定时器按时将当前流量写入文件
		trafficToMap(filePath);
		
		ScheduledExecutorService ses0=threadPoolService.getScheduledExecutor();
		//对流收集器进行扩展，收集信息的过程采用原代码，主要扩展的是后续处理
		initTimer = new SingletonTask(ses0, /*new Runnable()*/ new Runnable(){
			@Override
			public void run(){
				
				normalPorts.addAll(rank.keySet());
				
				for(DatapathId switchId : portsInBind.keySet()) {
					IOFSwitch sw=switchService.getSwitch(switchId);
					for(OFPort port : sw.getEnabledPortNumbers()) {
						if(rank.containsKey(new SwitchPort(switchId, port))) continue;
						Match.Builder mb = OFFactories.getFactory(OFVersion.OF_13).buildMatch();
						mb.setExact(MatchField.IN_PORT, port);
						
						List<OFInstruction> instructions = new ArrayList<>();
						instructions.add(OFFactories.getFactory(OFVersion.OF_13).instructions().gotoTable(FLOW_TABLE_ID));
						log.info("add reliable switch port static match rule"+switchId+"----"+port);
						saviProvider.doFlowAdd(switchId, STATIC_TABLE_ID, mb.build(), null, instructions, RELIABLE_PORT_PRIORITY);
					}
				}
				
				for(SwitchPort switchPort : rank.keySet()) {
					hostsCredit.put(switchPort, 24);
					logFlag.put(switchPort, true);
				}
				
//				super.run();
				//上面处理完后，packetOfFlows里面应该就有值了
				/*
				Set<SwitchPort> switchPorts = new HashSet<>();
				//注意：20s后收集一次，得到的dropRate其实就是这20s累计的丢包情况
				for(SwitchPort switchPort : rank.keySet()){
					//丢包率小于阈值，将对应交换机流表删除，这里值为0.2
					if(isNormal(switchPort)){
						switchPorts.add(switchPort);
						//加入正常端口列表
						normalPorts.offer(switchPort);
					}
					//其他端口加入异常端口列表
					else {
						abnormalPorts.offer(switchPort);
					}
				}
				doFlowRemove(switchPorts);
				*/ 
//				doFlowRemove(rank.keySet());
//				for(DatapathId swId : portsInBind.keySet()) {
//					convertFlag.put(swId, true);
//				}
				
				//初始阶段的最后，发出信号，进入下一阶段，此时要打开两个数据收集线程
				enableAnalysis(true);
				StringBuffer sb = new StringBuffer();
				testPortSet(sb, normalPorts, "normal");
				testPortSet(sb, observePorts.keySet(), "observe");
				testPortSet(sb, abnormalPorts, "abnormal");
				log.info("第一次得到的主机集合"+sb.toString());
				enablePortHandle();
				//记录时间
				stableTime=System.currentTimeMillis();
			}
		});
		//initTimer.reschedule(initInterval, TimeUnit.MINUTES);
		initTimer.reschedule(33, TimeUnit.SECONDS);
	}
	
	private void doFlowRemove(Set<SwitchPort> switchPorts) {
		List<FlowAction> removeActions = new ArrayList<>();
		for(SwitchPort switchPort : switchPorts) {
			Match.Builder mb=OFFactories.getFactory(OFVersion.OF_13).buildMatch();
			mb.setExact(MatchField.IN_PORT, switchPort.getPort());
			removeActions.add(FlowActionFactory.getFlowRemoveAction(switchPort.getSwitchDPID(), DYNAMIC_TABLE_ID, mb.build()));
			packetOfFlows.remove(switchPort);
		}
		saviProvider.pushFlowActions(removeActions);
		
	}
	/*
	private void doFlowRemove(Set<SwitchPort> switchPorts){
		List<Binding<?>> bindings = saviProvider.getBindings();
		List<FlowAction> removeActions = new ArrayList<>();
		//还是根据Set<SwitchPort>统一处理吧，否则效率太低
		for(Binding<?> binding : bindings) {
			if(switchPorts.contains(binding.getSwitchPort())){
				//针对每个端口，下发规则
				Match.Builder mb = OFFactories.getFactory(OFVersion.OF_13).buildMatch();
				mb.setExact(MatchField.IN_PORT, binding.getSwitchPort().getPort());
				removeActions.add(FlowActionFactory.getFlowRemoveAction(binding.getSwitchPort().getSwitchDPID(), DYNAMIC_TABLE_ID, mb.build()));
				
				//这里移除感觉可以增加效率
				switchPorts.remove(binding.getSwitchPort());
			}
		}
		//这里调试一下，经过上述过程，输入的所有端口应该都处理完被移除，如果不空那就可能出了问题
		if(switchPorts.size() != 0){
			log.error("DA doFlowRemove line:327 ，switchPorts没有处理完，还剩{}",switchPorts);
		}
		saviProvider.pushFlowActions(removeActions);
	}
*/	
	private void doFlowAdd(Set<SwitchPort> switchPorts){
		List<Binding<?>> bindings = saviProvider.getBindings();
		List<FlowAction> addActions = new ArrayList<>();
		for(Binding<?> binding : bindings) {
			if(switchPorts.contains(binding.getSwitchPort())){
				Match.Builder mb = OFFactories.getFactory(OFVersion.OF_13).buildMatch();
				Match.Builder mb2 = OFFactories.getFactory(OFVersion.OF_13).buildMatch();
				mb.setExact(MatchField.ETH_SRC, binding.getMacAddress());
				mb.setExact(MatchField.ETH_TYPE, EthType.IPv6);
				mb.setExact(MatchField.IPV6_SRC, (IPv6Address)binding.getAddress());
				mb.setExact(MatchField.IN_PORT, binding.getSwitchPort().getPort());

				mb2.setExact(MatchField.IN_PORT, binding.getSwitchPort().getPort());

				//另外定义转发动作
				List<OFInstruction> instructions = new ArrayList<>();
				instructions.add(OFFactories.getFactory(OFVersion.OF_13).instructions().gotoTable(FLOW_TABLE_ID));
				addActions.add(FlowActionFactory.getFlowAddAction(
						binding.getSwitchPort().getSwitchDPID(), 
						DYNAMIC_TABLE_ID, mb.build(), null, instructions, rank.get(binding.getSwitchPort())));
				addActions.add(FlowActionFactory.getFlowAddAction(
						binding.getSwitchPort().getSwitchDPID(), 
						DYNAMIC_TABLE_ID, mb2.build(), null, null, rank.get(binding.getSwitchPort())-1));
				//这里移除感觉可以增加效率
				switchPorts.remove(binding.getSwitchPort());
			}
		}
		if(switchPorts.size() != 0){
			log.error("DA doFlowAdd line:509 ，switchPorts没有处理完，还剩{}",switchPorts);
		}
		saviProvider.pushFlowActions(addActions);
	}
	
	private void doFlowMod(Set<SwitchPort> switchPorts){
		doFlowMod(switchPorts, DYNAMIC_TABLE_ID);
	}
	
	private void doFlowMod(Set<SwitchPort> switchPorts, TableId tableId){
		List<Binding<?>> bindings = saviProvider.getBindings();
		List<FlowAction> modActions = new ArrayList<>();
		for(Binding<?> binding : bindings) {
			if(switchPorts.contains(binding.getSwitchPort())){
				Match.Builder mb = OFFactories.getFactory(OFVersion.OF_13).buildMatch();
				Match.Builder mb2 = OFFactories.getFactory(OFVersion.OF_13).buildMatch();
				mb.setExact(MatchField.ETH_SRC, binding.getMacAddress());
				mb.setExact(MatchField.ETH_TYPE, EthType.IPv6);
				mb.setExact(MatchField.IPV6_SRC, (IPv6Address)binding.getAddress());
				mb.setExact(MatchField.IN_PORT, binding.getSwitchPort().getPort());
				
				List<OFInstruction> instructions = new ArrayList<>();
				instructions.add(OFFactories.getFactory(OFVersion.OF_13).instructions().gotoTable(FLOW_TABLE_ID));
				
				if(tableId.equals(DYNAMIC_TABLE_ID)) {
					mb2.setExact(MatchField.IN_PORT, binding.getSwitchPort().getPort());
					modActions.add(FlowActionFactory.getFlowModAction(binding.getSwitchPort().getSwitchDPID(), 
							tableId, mb2.build(), null, null, rank.get(binding.getSwitchPort())-1,0,0));
				}
				
				modActions.add(FlowActionFactory.getFlowModAction(binding.getSwitchPort().getSwitchDPID(), 
						tableId, mb.build(), null, instructions, rank.get(binding.getSwitchPort()), 0, 0));
				
				//这里移除感觉可以增加效率
				switchPorts.remove(binding.getSwitchPort());
			}
		}
		if(switchPorts.size() != 0){
			log.error("DA doFlowAdd line:509 ，switchPorts没有处理完，还剩{}",switchPorts);
		}
		saviProvider.pushFlowActions(modActions);
	}
	private void startStatisticsCollector() {
		//下面interval，前者表示几秒后开始，后者表示启动间隔
		flowSchedule=threadPoolService.getScheduledExecutor().scheduleAtFixedRate(
				new FlowStatisCollector(), flowStasInterval*500, flowStasInterval*1000, TimeUnit.MILLISECONDS);
		portPackets = threadPoolService.getScheduledExecutor().scheduleAtFixedRate(
				new PortPacketsCollector(), flowStasInterval*500, flowStasInterval*1000, TimeUnit.MILLISECONDS);
	}
	

	//通过rest api初始化网络，只有初始化网络后，三个集合才有值
	@Override
	public synchronized void changeStatusByRest(int flag) {
		//如果从rest api接收到的是0，表示执行一次初始阶段的代码
		if(flag == INIT_STAGE) {
			System.out.println("边缘交换机端口：" + rank.keySet().size());
			for(DatapathId dpid : portsInBind.keySet()) {
				System.out.println(dpid.getLong());
			}
//			firstStage(threadPoolService.getScheduledExecutor());
			firstStage();
		}
	}

	//通过rest api开启DA模块，但是这个功能好像在前端并没有体现出来，不通过rest api也是自动开启的
	//但是查看了一下，如果不通过rest api的话，isEnable应该一直都是false啊，然后如果这个地方没有被调用的话，感觉数据收集没法做啊
	@Override
	public synchronized void enableAnalysis(boolean flag) {
		// 启用该模块
		if (flag && !isEnable) {
			startStatisticsCollector();
			isEnable = true;
		} else if (!flag && isEnable) {
			stopStatsCollector();
			isEnable = false;
		}
	}
	
	private void stopStatsCollector(){
		if(! flowSchedule.cancel(false)) {
			log.error("Could not cancel flow stats thread");
		}
		else {
			log.warn("Statistics collection thread(s) stopped");
		}
		
		if(! portPackets.cancel(false)) {
			log.error("Could not cancel flow stats thread");
		}
		else {
			log.warn("Statistics collection thread(s) stopped");
		}
	}
	
	public void enablePortHandle() {
		//System.out.println("开启端口处理线程======================");
		//4s后开始执行，每隔6s执行一次
		normalPortSchedule = threadPoolService.getScheduledExecutor().
				scheduleAtFixedRate(new NormalPortThread(), flowStasInterval*220, flowStasInterval*1000, TimeUnit.MILLISECONDS);
		//5s后开始执行，每隔6s执行一次
		observePortSchedule =threadPoolService.getScheduledExecutor().
				scheduleAtFixedRate(new ObservePortThread(), flowStasInterval*230, flowStasInterval*1000, TimeUnit.MILLISECONDS);
		//5s后开始执行，每隔6s执行一次
		abnormalPortSchedule = threadPoolService.getScheduledExecutor()
				.scheduleAtFixedRate(new AbnormalPortThread(), flowStasInterval*210, flowStasInterval*1000, TimeUnit.MILLISECONDS);
	}

	private class NormalPortThread extends Thread {
		@Override
		public void run() {
//			System.out.println("normal =================");
			
			for(SwitchPort sp : saviProvider.getPushFlowToSwitchPorts().keySet()) 
				if(normalPorts.contains(sp)) normalPorts.remove(sp);
			
			SwitchPort cur = null;
			Set<SwitchPort> handleSet = new HashSet<>();
//			getChangeNormalPorts(STATUS);
			Iterator<SwitchPort> iterator = normalPorts.iterator();
			while(iterator.hasNext()){
				cur = iterator.next();
				if(!rightPorts.contains(cur)){
					//这里之前忘记对异常端口采取措施了
					abnormalPorts.offer(cur);

					//计算这个交换机上的异常端口数
					countAbnormalPort(cur.getSwitchDPID(),true);
					
					handleSet.add(cur);
					iterator.remove();
					
				}
			}

			int level = getLevelByQueueSize();
			if(level == 0) {
				normalNum = 2;
			}
			else {
				normalNum = 3;
			}
			for(int i = 0 ; i < normalNum ; i++){
				cur = normalPorts.poll();
				//当获取元素为空，退出循环统一处理
				if(cur == null) break;
				handleSet.add(cur);
				//第一次放到观察列表，设置次数为0，方便观察线程处理
				observePorts.put(cur, 0);
				pickFromNormal.add(cur);
			}
			
			
//			for(int i=0;i<3;i++) {
//				SwitchPort sp=normalPorts.poll();
//				if(sp==null) break;
//				handleSet.add(sp);
//			}
			
			//对选中的端口下发验证规则
			doFlowAdd(handleSet);
			
		}
	}
	
	
	private class AbnormalPortThread extends Thread {
		@Override
		public void run() {
//			System.out.println("abnormal ===================");
			//1.找出本次统计中，变得正常的端口，包括其他队列的元素
//			getChangeNormalPorts(STATUS);
			//2.选出和abnormalPorts的交集，移出到观察队列
			//不过这里用size可能很不妥，毕竟多线程环境下
			//不管queue.size是否中途变化，循环只做curSize次，curSize应该不变吧（大概）
			
			//修改异常端口匹配优先级（依然是异常的端口）
			int curSize = abnormalPorts.size();
			for(int i = 0 ; i < curSize ; i++){
				SwitchPort cur = abnormalPorts.poll();
				//这里用continue还是break也是问题，直接用break等下一次处理吧，用continue很可能突然新增了个元素然后处理，逻辑很麻烦
				if(cur == null) break;
				//如果端口变正常，需要移出到观察队列
				if(rightPorts.contains(cur)){
					
					observePorts.put(cur, 0);
					//这一步仅仅为了加快点效率，不排除出错的可能（abnormalPorts有重复元素这一步可能出错）
					//有重复元素是逻辑问题，只是重复的那个会默认加到ab队尾（同时存在于两个队列），如果没有这句，也只是上面put两次而已，覆盖掉原来的
					//normals.remove(cur);
					countAbnormalPort(cur.getSwitchDPID(), false);
				}                                                           
				else {
					//否则加入队尾
					abnormalPorts.offer(cur);
					
				}
			}
			//多线程环境下，由于curSize可能变动，该线程自己会造成元素减少，其他线程只可能造成其元素增多
			//想不明白了，10s的时间间隔减少多线程的不确定性
			
		}
	}
	
	
	private class ObservePortThread extends Thread {
		@Override
		public void run() {
//			System.out.println("observe ===================");
			//对观察列表的处理是最麻烦的，它的端口有两种转换状态，而循环中对状态的修改感觉很不妥
			//1.同样获取该轮的正常端口
//			getChangeNormalPorts(STATUS);
			//放回正常队列，撤销规则的端口列表
			Set<SwitchPort> actionPorts = new HashSet<>();
			//循环遍历修改吧，出错也没办法了
			Iterator<Map.Entry<SwitchPort, Integer>> iterator = observePorts.entrySet().iterator();
			
			while(iterator.hasNext()){
				Map.Entry<SwitchPort, Integer> entry = iterator.next();
				if(rightPorts.contains(entry.getKey())){
					//发现该端口正常，正常次数超过3就移出
					if(entry.getValue() >= 6-hostsCredit.get(entry.getKey())/8) {
						//注意，先放到正常队列，再从map移出，这里其实是一个对象被引用到了不同容器，不知道会不会出问题
						normalPorts.offer(entry.getKey());
						pickFromNormal.remove(entry.getKey());
						actionPorts.add(entry.getKey());
						iterator.remove();
					}
					else {
						//观察次数不够，只修改次数
						observePorts.put(entry.getKey(), entry.getValue() + 1);
					}
				}
				else {
					//发现当前端口不正常，移出到异常队列
					abnormalPorts.offer(entry.getKey());
					
					countAbnormalPort(entry.getKey().getSwitchDPID(), true);
					pickFromNormal.remove(entry.getKey());
					iterator.remove();
				}
			}
			//遍历完成后，对移出到正常队列的端口撤销验证规则
			doFlowRemove(actionPorts);
		}
	}
	
	private boolean isNormal(SwitchPort switchPort) {
		//注意，这里可以根据三个队列的长度比重，修改阈值（暂时去掉丢包率为1的边缘情况——样本过于偏差，虽然确实有可能丢包率为1，但前提是丢包数本身也很大）
		// || entry.getValue().getLossRate() == 1
	//	System.out.println("交换机：" + entry.getKey().getSwitchDPID().getLong() + "端口：" + entry.getKey().getPort().getPortNumber() +"丢包率：" + entry.getValue().lossRate + "丢包个数：" + entry.getValue().lossNum + "累计丢包率：" + entry.getValue().getAccumulateLossRate() + ",累计丢包个数：" + entry.getValue().accumulateLossNum);
		if(packetOfFlows.get(switchPort)==null) return true;
		if(packetOfFlows.get(switchPort).getLossRate()!=1&&packetOfFlows.get(switchPort).getLossRate() > LOSS_RATE_THRESHOLD) {
			int t=hostsCredit.get(switchPort)-2>0?hostsCredit.get(switchPort)-2:0;
			hostsCredit.put(switchPort, t);
			//log
			if(logFlag.get(switchPort)) {
				writeErrorLog(switchPort, true);
				logFlag.put(switchPort, false);
			}
			return false;
		}
		if(packetOfFlows.get(switchPort).getLossNum() > LOSS_NUM_THRESHOLD) {
			int t=hostsCredit.get(switchPort)-2>0?hostsCredit.get(switchPort)-2:0;
			hostsCredit.put(switchPort, t);
			//log
			if(logFlag.get(switchPort)) {
				writeErrorLog(switchPort, true);
				logFlag.put(switchPort, false);
			}
			return false;
		}
		int t=hostsCredit.get(switchPort)+1<47?hostsCredit.get(switchPort)+1:47;
		hostsCredit.put(switchPort, t);
		//log
		if(!logFlag.get(switchPort)) {
			writeErrorLog(switchPort, false);
			logFlag.put(switchPort, true);
		}
		return true;
	}
	
	
	private Set<SwitchPort> getChangeNormalPorts(int type){
		rightPorts.clear();
		//目前只按丢包率，以后扩展其他分支即可
		if(type == PLAN_LOSSRATE){
			
//			StringBuffer test = new StringBuffer();
			for(SwitchPort switchPort : rank.keySet()){
				if(isNormal(switchPort)) {
					rightPorts.add(switchPort);
//					test.append(computeTerminatorNum(entry.getKey()) + ",");
				}
			}
			
			return rightPorts;
		}
		//按照数据流量来获取正常端口
		//这部分代码是针对9主机的固定场景，如果想要更通用、标准，请修改trafficToMap以及更新相应文件的方法
		else if(type == PLAN_TRAFFIC){
			Map<Integer, Double> testMap = new HashMap<>();
			//flag用来判断是否发生峰值更新
			boolean flag = false;
			
			//将当前轮次，端口的流量数据和maxTraffic相比较
			//Set<SwitchPort> result = new HashSet<>();
			//从inPortPackets里面获取到的是所有端口，包括非主机端口，需要想个办法进行过滤
			//上面packetOfFlows之所以可以，是因为当初统计时只针对验证规则在统计，而验证规则恰好只针对主机端口
			//这里先取巧，以后再相办法改进吧，改进思路就是根据saviProvider.getBindings
			for(Map.Entry<SwitchPort, U64> entry : inPortPacketsRes.entrySet()){
				SwitchPort swport = entry.getKey();
				//排除掉00::01和-4，即1-1,1-2,1-3,2-4,3-4,4-4
//					if(!swport.getSwitchDPID().toString().contains("01") &&
//							swport.getPort().getPortNumber() != -2 && swport.getPort().getPortNumber() != 4){
				if(rank.containsKey(swport)){
					//将端口转主机编号，因为文件里面读取出来的就是主机编号
					int terminatorNum = computeTerminatorNum(swport);
					//计算当前速率
					double v = entry.getValue().getValue()/(1.0 * flowStasInterval);
					testMap.put(terminatorNum, maxTraffics.get(terminatorNum));
					
					//log.info(tempNum + " curV:" + v + " maxV:" + maxTraffics.get(tempNum));
					
					//当速率超过历史峰值时，加入异常端口集合，更新历史峰值，最后更新峰值文件
					if(v > maxTraffics.get(terminatorNum)){
						flag = true;
						//这一句放在后面测试一下，只有正常流量才更新峰值，这样下一次检测时获取到的还是正常的峰值
						//maxTraffics.put(tempNum, v);
						
						//DecimalFormat df = new DecimalFormat("#####0.00");
						//int curOut = getOutPacketsByPort(swport);
						
						//当峰值发生变化时，统计同一交换机的其他端口流量总和，以初步判断是正常还是异常流量
						//而这个值是根据是否剧烈变化来判断是否正常的，定义剧烈变化就得和上一次的数据进行比较
						double curOut = getOutPacketsByPort(swport)/(1.0 * flowStasInterval);
						
						//超过当前最大峰值
						log.info("当前入流量" + v + "超过历史峰值" + maxTraffics.get(terminatorNum));
//							log.info(tempNum + " curOut - map：" + curOut + " - " + (outTraffics.get(tempNum)/(2.0 * flowStasInterval)) + " = " + (curOut - outTraffics.get(tempNum)/(2.0 * flowStasInterval))
//									+ " curInV - map：" + v + " - " + maxTraffics.get(tempNum) + " = " + (v - maxTraffics.get(tempNum)));
//							double curRate = 1.0 * (v - maxTraffics.get(tempNum))/(curOut - outTraffics.get(tempNum)/(2.0 * flowStasInterval));
//							log.info(tempNum + " in/out增比：" + curRate);
//							
						//如果这个值变化特别剧烈，in、out同时波动强烈，说明是正常流量；如果in变化而out不怎么变化，那就是异常流量了（注意，这里的out是同一交换机的其他端口的out之和）
						//但是这里这个判断只能生效一次，之后由于是平稳的高流量，就会多次进入else，被判定为异常端口了。
						if(curOut > (outTraffics.get(terminatorNum) * 1.3)){
						//if(curRate > outTraffics.get(tempNum)){
							//说明是正常端口，正常端口才更新outTraffics，不要让异常数据影响
							rightPorts.add(swport);
							//log.info("========if内 " + tempNum + " curOut：" + curOut + " outMap：" + outTraffics.get(tempNum));
							log.info("正常大流量 curOut：" + curOut + " map：" + outTraffics.get(terminatorNum));
							//outTraffics.put(tempNum, curRate);
							maxTraffics.put(terminatorNum, v);
						}
						//异常端口的情况，不应该更新峰值
						else{
							flag = false;
						}
					}
					else {
						rightPorts.add(swport);
					}
				}
			}
			//如果发生了峰值更新，最后更新文件
			if(flag){
				StringBuffer sb = new StringBuffer();
				for(Map.Entry<Integer, Double> entry : maxTraffics.entrySet()){
					//试了一下，\r\n是当前行的字符，也就是说最后一行是空行
					sb.append(entry.getKey() + " " + entry.getValue() + "\r\n");
				}
				System.out.println("=============更新峰值文件，h1：" + maxTraffics.get(1) + "=============");
				writeToTxt(filePath, false, sb.toString());
				
			}
			return rightPorts;
		}
		
		return null;
	}
	//获取当前交换机的所有出口流量 
	private int getOutPacketsByPort(SwitchPort sp){
		if(outTraffics.size() < 1){
			for(int i = 1; i <= rank.size(); i++){
				outTraffics.put(i, 0.0);
			}
		}
		long pnum = 0;
		//由于传入的只是一个端口，那就不刷新整个端口的变化情况了？还是说，整个端口的变化情况也要每s刷新？
		//刷新的问题不应该由这个方法来解决，这个方法只是返回需要的出流量而已
		//想了下，实时刷新不可取，因为实时刷新时，对于判断为流量异常的端口可能就把数据更新了
		for(SwitchPort cur : outPortPacketsRes.keySet()){
			//找到同一个交换机的其他端口，需要排除掉不知道什么用的local端口
			if(cur.getSwitchDPID().equals(sp.getSwitchDPID()) && rank.containsKey(cur)){
				pnum += outPortPacketsRes.get(cur).getValue();
			}
		}
		
		//System.out.println(((int)sp.getSwitchDPID().getLong() - 2) * 3 + sp.getPort().getPortNumber() + " "  + pnum + "==========");
		return (int) pnum;
	}
	
	
	//通过队列长度比例，确定当前阈值的级别，后续可以扩展为更加复杂的规则
	//这里就随便想一点听起来合理的
	private int getLevelByQueueSize() {
		if(observePorts.size() > normalPorts.size()/2 &&observePorts.size() > abnormalPorts.size()){
			return 0;
		}
		else {
			return 1;
		}
	}
	
	
	//接下来要定义几个线程内部类
	private class FlowStatisCollector extends Thread{
		@Override
		public void run(){
			//首先获取交换机的响应信息
//			long t=System.currentTimeMillis();
//			System.out.println("DataAnalysis.FlowStatisCollector.run()----start"+t);
			
			Map<DatapathId, List<OFStatsReply>> map = getSwitchStatistics(portsInBind.keySet(), OFStatsType.FLOW);
			
//			if(map==null) return;
			for(Map.Entry<DatapathId, List<OFStatsReply>> entry : map.entrySet()){
				DatapathId swid = entry.getKey();
				if(swid == null || entry.getValue() == null) continue;
				for(OFStatsReply r :entry.getValue()){
					OFFlowStatsReply psr = (OFFlowStatsReply) r;
					for(OFFlowStatsEntry psrEntry : psr.getEntries()){
						//目前只统计验证规则和通配规则
						int priority = psrEntry.getPriority();
						if(priority < BINDING_PRIORITY-1&&priority>2*priorityLevel) continue;
						OFPort port = psrEntry.getMatch().get(MatchField.IN_PORT);
						if(port == null) continue;
						SwitchPort swport = new SwitchPort(swid , port);
						PacketOfFlow packetOfFlow = packetOfFlows.get(swport);
						if(psrEntry.getMatch().isExact(MatchField.IPV6_SRC)){
							if(packetOfFlow == null){
								//该分支表示正常数据包数，所以最后两个和丢包率有关的字段初始化为0
								packetOfFlow= new PacketOfFlow(psrEntry.getPacketCount().getValue(), 0 , psrEntry.getPacketCount().getValue() , 0 , 0 , 0);
							}else{
								packetOfFlow.setPassNum(psrEntry.getPacketCount().getValue() - packetOfFlow.getAccumulatePassNum());
								packetOfFlow.setAccumulatePassNum(psrEntry.getPacketCount().getValue());
								//这里有点麻烦，由于匹配成功的数据包数变了，那么丢包率也会发生变动
								long fenmu1 = packetOfFlow.getLossNum() + packetOfFlow.getPassNum();
								packetOfFlow.setLossRate(fenmu1 == 0 ? 0 : (packetOfFlow.getLossNum()*1.0)/fenmu1);
								long fenmu2 = packetOfFlow.getAccumulateLossNum() + packetOfFlow.getAccumulatePassNum();
								packetOfFlow.setAccumulateLossRate(fenmu2 == 0 ? 0 : (packetOfFlow.getAccumulateLossNum()*1.0 / fenmu2));
							}
						}else{
							if(packetOfFlow == null){
								packetOfFlow=new PacketOfFlow(0, psrEntry.getPacketCount().getValue(),0, psrEntry.getPacketCount().getValue() , 0 , 0);
							}else{
								packetOfFlow.setLossNum(psrEntry.getPacketCount().getValue()-packetOfFlow.getAccumulateLossNum());
								packetOfFlow.setAccumulateLossNum(psrEntry.getPacketCount().getValue());
								//修改后的代码逻辑存在很大弱点，太依赖于流表规则的正确性了，一旦流表规则出了问题，比如只有验证的，没有配套的，那么这里的统计基本全有问题
								long fenmu1 = packetOfFlow.getLossNum() + packetOfFlow.getPassNum();
								packetOfFlow.setLossRate(fenmu1 == 0 ? 0 : (packetOfFlow.getLossNum()*1.0)/fenmu1);
								long fenmu2 = packetOfFlow.getAccumulateLossNum() + packetOfFlow.getAccumulatePassNum();
								packetOfFlow.setAccumulateLossRate(fenmu2 == 0 ? 0 : (packetOfFlow.getAccumulateLossNum()*1.0 / fenmu2));
							}
						}
						packetOfFlows.put(swport, packetOfFlow);
//						if(packetOfFlow.getlossRate()<LOSS_RATE_THRESHOLD) {
//							rightPorts.add(swport);
//						}else if(packetOfFlow.getLossNum()<LOSS_NUM_THRESHOLD) {
//							rightPorts.add(swport);
//						}else {
//							specificPorts.add(swport);
//						}
//						if(swport.getSwitchDPID().getLong()==7&&swport.getPort().getPortNumber()==3) {
//							System.out.println("!!!!!!!!!!!!!!!!!"+packetOfFlow.getPassNum()+"!!!!!!!!!!!!!!!!!!!"+psrEntry.getDurationNsec());
//							System.out.println("<<<<<<<<<<<<<<<<<"+packetOfFlow.getAccumulatePassNum()+">>>>>>>>>>>>>>>>>>>"+psrEntry.getDurationSec());
//						}
					}
				}
			}
			//writeToTxt(filePath, true, temp.toString());
//			for(SwitchPort switchPort : rightPorts) {
//				classify(switchPort);
//			}
			getChangeNormalPorts(STATUS);
//			System.out.println("DataAnalysis.FlowStatisCollector.run()----end"+(System.currentTimeMillis()-t));
		}
	}
	/*
	private void classify(SwitchPort switchPort) {
		if(observePorts.containsKey(switchPort)) {
			if(observePorts.get(switchPort)>=2) {
				normalPorts.offer(switchPort);
				observePorts.remove(switchPort);
				
				Match.Builder mb=OFFactories.getFactory(OFVersion.OF_13).buildMatch();
				mb.setExact(MatchField.IN_PORT, switchPort.getPort());
				saviProvider.doFlowRemove(switchPort.getSwitchDPID(), DYNAMIC_TABLE_ID, mb.build());
				
			}else {
				observePorts.put(switchPort, observePorts.get(switchPort)+1);
			}
		}else if(handleSet.contains(switchPort)) {
			normalPorts.offer(switchPort);
		}else {
			abnormalPorts.remove(switchPort);
			observePorts.put(switchPort, 0);
		}
	}
	*/
	//并发读写文件，需慎重，一旦抛出异常，定时器就会中断了
	private void writeToTxt(String filePath, boolean append, String text) {	
        RandomAccessFile fout = null;
        FileChannel fcout = null;
        try {
        	File file = new File(filePath);
        	//2018-4-10 判断文件是否存在，不存在则创建，之前maxTraffic在trafficToMap处理了空文件的问题，所以没报错
        	if(!file.exists()){
        		file.createNewFile();
        	}
            fout = new RandomAccessFile(file, "rw");
            long filelength = fout.length();//获取文件的长度
            //如果是追加，将文件指针定位到文件末尾
            if(append){
            	fout.seek(filelength);
            }
            else{
            	fout.seek(0);
            }
            fcout = fout.getChannel();//打开文件通道
            FileLock flout = null;
            
            //请求一次锁，只要没请求到，就放弃
            try {
                flout = fcout.tryLock();
            } catch (Exception e) {
            	//请求不到锁会进入这里
                System.out.print("lock is exist ......");
                return;
            }
            //到这步就持有锁了，开始写文件
            fout.write(text.getBytes());//将需要写入的内容写入文件

            flout.release();
            fcout.close();
            fout.close();

        } catch (IOException e1) {
            e1.printStackTrace();
            System.out.print("file no find ...");
        } finally {
            if (fcout != null) {
                try {
                    fcout.close();
                } catch (IOException e) {
                    e.printStackTrace();
                    fcout = null;
                }
            }
            if (fout != null) {
                try {
                    fout.close();
                } catch (IOException e) {
                    e.printStackTrace();
                    fout = null;
                }
            }
        }
	}
	
	/*private void writeToTxt(String filePath, boolean append, String text) {	
		try {
			synchronized (filePath) {
				BufferedWriter out = new BufferedWriter(new FileWriter(filePath, append));
				try {
					out.write(text);
					out.flush();
				} finally {
					out.close();
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}*/
	
	
	//该线程类用来获取单个交换机的流表统计信息
	private class GetStatisticsThread extends Thread{
		List<OFStatsReply> replies;
		DatapathId dpId;


		OFStatsType statsType;
		
		public GetStatisticsThread(DatapathId dpId , OFStatsType statsType){
			this.statsType=statsType;
			this.dpId=dpId;
			this.replies=null;
		}
		
		public List<OFStatsReply> getReplies() {
			return replies;
		}
		public DatapathId getDpId() {
			return dpId;
		}
		@Override
		public void run(){
			replies=getSwitchStatistics(dpId, statsType);
		}
	}
	
	//该方法使用多线程对多个交换机进行流统计信息的请求
	protected Map<DatapathId, List<OFStatsReply>> getSwitchStatistics(Set<DatapathId> dpIds , OFStatsType statsType){
//		if(dpIds==null||dpIds.isEmpty())  return null;
		Map<DatapathId, List<OFStatsReply>> replies = new HashMap<>();
		//活跃线程、等待被移除线程列表
		List<GetStatisticsThread> activeThreads = new ArrayList<>(dpIds.size());
		List<GetStatisticsThread> pendingRemovalThreads = new ArrayList<>();
		GetStatisticsThread t;
		//没有判定是否是接入层交换机
		for(DatapathId dpId : dpIds){
			if(statsType.equals(OFStatsType.FLOW)&&staticSwId.contains(dpId)) continue;
			t = new GetStatisticsThread(dpId, statsType);
			activeThreads.add(t);
			t.start();
		}
		
		// 这里是0.4s，具体的要根据拓扑测出来
		//接下来就是在0.4s内上面的收集线程要全部收集完毕，对于收集完毕的线程结束即可
		//收集间隔flowStasInterval被设定为0.4s，因此在0.4s内必须完成收集工作
		for(int sleepCycle = 0 ; sleepCycle < 2 ; sleepCycle++){
			//首先扫描活跃线程列表，遇到结束的加入移除列表
			for(GetStatisticsThread curThread : activeThreads){
				if(curThread.getState() == State.TERMINATED){
					replies.put(curThread.getDpId(), curThread.getReplies());
					pendingRemovalThreads.add(curThread);
				}
			}
			
			for(GetStatisticsThread curThread : pendingRemovalThreads){
				activeThreads.remove(curThread);
			}
			//因为下次开始，移除列表需要要为空，所以这里清除
			pendingRemovalThreads.clear();
			
			if(activeThreads.isEmpty()){
				break;
			}
			
			try{
				Thread.sleep(500);
			}
			catch(InterruptedException e){
				log.error("Interrupted while waiting for statistics", e);
			}
		}
		return replies;
	}
	
	
	//该方法为获取单个交换机的某种类型统计信息
	//除了Flow，其他这里都没用到
	@SuppressWarnings("unchecked")
	protected List<OFStatsReply> getSwitchStatistics(DatapathId swId , OFStatsType statsType){
		IOFSwitch sw=switchService.getSwitch(swId);
		ListenableFuture<?> future;
		List<OFStatsReply> values=null;
		Match match;
		if(sw!=null){
			OFStatsRequest<?> request = null;
			switch(statsType){
			case FLOW:
				match = sw.getOFFactory().buildMatch().build();
				request = sw.getOFFactory().getVersion().compareTo(OFVersion.OF_10) == 0 
						? sw.getOFFactory().buildFlowStatsRequest().setMatch(match).setOutPort(OFPort.ANY)
						.setTableId(DYNAMIC_TABLE_ID).build()
						: sw.getOFFactory().buildFlowStatsRequest().setMatch(match).setOutPort(OFPort.ANY)
						.setTableId(DYNAMIC_TABLE_ID).setOutGroup(OFGroup.ANY).build();
						
				break;
			case AGGREGATE:
				match = sw.getOFFactory().buildMatch().build();
				request = sw.getOFFactory().buildAggregateStatsRequest().setMatch(match).setOutPort(OFPort.ANY)
						.setTableId(TableId.ALL).build();
				break;
			case PORT:
				request = sw.getOFFactory().buildPortStatsRequest().setPortNo(OFPort.ANY).build();
				break;
			case QUEUE:
				request = sw.getOFFactory().buildQueueStatsRequest().setPortNo(OFPort.ANY)
						.setQueueId(UnsignedLong.MAX_VALUE.longValue()).build();
				break;
			case DESC:
				request = sw.getOFFactory().buildDescStatsRequest().build();
				break;
			case GROUP:
				if (sw.getOFFactory().getVersion().compareTo(OFVersion.OF_10) > 0) {
					request = sw.getOFFactory().buildGroupStatsRequest().build();
				}
				break;

			case METER:
				if (sw.getOFFactory().getVersion().compareTo(OFVersion.OF_13) >= 0) {
					request = sw.getOFFactory().buildMeterStatsRequest().setMeterId(OFMeterSerializerVer13.ALL_VAL).build();
				}
				break;

			case GROUP_DESC:
				if (sw.getOFFactory().getVersion().compareTo(OFVersion.OF_10) > 0) {
					request = sw.getOFFactory().buildGroupDescStatsRequest().build();
				}
				break;

			case GROUP_FEATURES:
				if (sw.getOFFactory().getVersion().compareTo(OFVersion.OF_10) > 0) {
					request = sw.getOFFactory().buildGroupFeaturesStatsRequest().build();
				}
				break;

			case METER_CONFIG:
				if (sw.getOFFactory().getVersion().compareTo(OFVersion.OF_13) >= 0) {
					request = sw.getOFFactory().buildMeterConfigStatsRequest().build();
				}
				break;

			case METER_FEATURES:
				if (sw.getOFFactory().getVersion().compareTo(OFVersion.OF_13) >= 0) {
					request = sw.getOFFactory().buildMeterFeaturesStatsRequest().build();
				}
				break;

			case TABLE:
				if (sw.getOFFactory().getVersion().compareTo(OFVersion.OF_10) > 0) {
					request = sw.getOFFactory().buildTableStatsRequest().build();
				}
				break;

			case TABLE_FEATURES:
				if (sw.getOFFactory().getVersion().compareTo(OFVersion.OF_10) > 0) {
					request = sw.getOFFactory().buildTableFeaturesStatsRequest().build();
				}
				break;
			case PORT_DESC:
				if (sw.getOFFactory().getVersion().compareTo(OFVersion.OF_13) >= 0) {
					request = sw.getOFFactory().buildPortDescStatsRequest().build();
				}
				break;
			case EXPERIMENTER:
			default:
				log.error("Stats Request Type {} not implemented yet", statsType.name());
				break;
			}
			
			try{
				if(request!=null){
					future = sw.writeStatsRequest(request);
					values = (List<OFStatsReply>) future.get(500, TimeUnit.MILLISECONDS);
				}
			}
			catch(Exception e){
				log.error("Failure retrieving statistics from switch {}. {}", sw, e);
			}
		}
		return values;
	}

	private class PortPacketsCollector implements Runnable {
		@Override
		public void run() {
//			System.out.println("port packets collector is running-------");
			Map<DatapathId, List<OFStatsReply>> replies = getSwitchStatistics(portsInBind.keySet(),OFStatsType.PORT);
//			if (replies == null)  return;
			for (Entry<DatapathId, List<OFStatsReply>> e : replies.entrySet()) {
				U64 maxInPacketNum=U64.ZERO;
				for (OFStatsReply r : e.getValue()) {
					OFPortStatsReply psr = (OFPortStatsReply) r;
					//psr size是该交换机端口数量，一般是一个local+几个物理端口
					//log.info("psr size:"+psr.getEntries().size());
					for (OFPortStatsEntry pse : psr.getEntries()) {
						//log.info(pse.toString());
						SwitchPort sp = new SwitchPort(e.getKey(), pse.getPortNo());
						U64 prePacketsNum;
						if (inPortPackets.containsKey(sp) || inTentativePortPackets.containsKey(sp)) {
							if (inPortPackets.containsKey(sp)) { /* update */
								prePacketsNum = inPortPackets.get(sp);
							} else if (inTentativePortPackets.containsKey(sp)) { /* finish */
								prePacketsNum = inTentativePortPackets.get(sp);
								inTentativePortPackets.remove(sp);
							} else {
								log.error("Inconsistent state between tentative and official port stats lists.");
								return;
							}
							
							//当前总包数-上一次总包数=时间段内包数
							U64 inPacketsCounted = pse.getRxPackets();
							U64 inPacketsNum=inPacketsCounted.subtract(prePacketsNum);
							inPortPackets.put(sp,inPacketsCounted);
							inPortPacketsRes.put(sp, inPacketsNum);
							
						} else { /* initialize */
							inTentativePortPackets.put(sp, pse.getRxPackets());
						}	
						if (outPortPackets.containsKey(sp) || outTentativePortPackets.containsKey(sp)) {
							if (outPortPackets.containsKey(sp)) { /* update */
								prePacketsNum = outPortPackets.get(sp);
							} else if (outTentativePortPackets.containsKey(sp)) { /* finish */
								prePacketsNum = outTentativePortPackets.get(sp);
								outTentativePortPackets.remove(sp);
							} else {
								log.error("Inconsistent state between tentative and official port stats lists.");
								return;
							}
							U64 outPacketsCounted = pse.getTxPackets();
							U64 outPacketsNum=outPacketsCounted.subtract(prePacketsNum);
							outPortPackets.put(sp,outPacketsCounted);
							outPortPacketsRes.put(sp, outPacketsNum);
	
						} else { /* initialize */
							outTentativePortPackets.put(sp, pse.getTxPackets());
						}
						
						if(rank.containsKey(sp)) {
							if(timeToSave) {
								packetsInRecord.put(sp, pse.getRxPackets());
							}
							if(cycleTime==0) {
								portsList.add(sp);
								packetsInPeriod.put(sp, pse.getRxPackets().subtract(packetsInRecord.get(sp)));
								if(packetsInPeriod.get(sp).compareTo(maxInPacketNum)>0) {
									maxInPacketNum=packetsInPeriod.get(sp);
								}
							}
						}
						
//						if(e.getKey().getLong()==7&&pse.getPortNo().getPortNumber()==3) {
//							log.info("(((((((((((((((((((("+pse.getRxPackets()+"))))))))))))))))"+pse.getDurationSec());
//						}
					}
				}
				
				if(cycleTime==0&&maxInPacketNum.getValue()!=0) {
					long d=maxInPacketNum.getValue()/priorityLevel>1?maxInPacketNum.getValue()/priorityLevel:1;
					for(SwitchPort sp : portsList) {
						U64 u=packetsInPeriod.get(sp);
						int priority=u.getValue()/d>BINDING_PRIORITY?(int)(u.getValue()/d):BINDING_PRIORITY;
						rank.put(sp, priority);
					}
				}
				portsList.clear();
				
			}
			
			if(timeToSave) {
				timeToSave=false;
			}
			if(cycleTime==0) {
				timeToSave=true;
				cycleTime=period;
				doFlowMod(new HashSet<>(abnormalPorts));
			}
			cycleTime--;
			
		}
	}
	
	@Override
	public U64 getInPacketsNum(DatapathId dpid, OFPort p) {
		return inPortPacketsRes.getOrDefault(new SwitchPort(dpid, p), U64.ZERO);
	}

	@Override
	public U64 getOutPacketsNum(DatapathId dpid, OFPort p) {
		return outPortPacketsRes.getOrDefault(new SwitchPort(dpid, p), U64.ZERO);
	}

	@Override
	public PacketOfFlow getPacketOfFlow(DatapathId dpid, OFPort p) {
		return packetOfFlows.get(new SwitchPort(dpid, p));
	}

	@Override
	public Object getAllPacketOfFlow() {
		List<Map.Entry<SwitchPort, PacketOfFlow>> temp = 
				new ArrayList<>(packetOfFlows.entrySet());
		Collections.sort(temp, new Comparator<Map.Entry<SwitchPort, PacketOfFlow>>() {
			@Override
			public int compare(Entry<SwitchPort, PacketOfFlow> o1, Entry<SwitchPort, PacketOfFlow> o2) {
				double cmp = o1.getValue().getLossRate() - o2.getValue().getLossRate();
				if(cmp < 0 ) 
					return 1;
				else if(cmp > 0)
					return -1;
				else
					return 0;
			}
		});
		//如果list再转map返回，map中的元素应该还是无序的，所以直接返回List
		//但这样从rest取出的json格式是{"key":"00:00:01-2","value":{}}，很不好看，怎么办呢？
		return temp;
	}

	
	public Object getPortSet() {
		Map<String, String> temp = new HashMap<>();
		//如何获取到的是完整的端口列表呢？ 
		//思路1：交给前端判断，只要前端得到的端口不全，就重复请求
		//思路2：控制时间参数，在端口集合的处理完之后，才获取；否则阻塞
		//很奇怪，在startup里面每秒获取一次，端口总是完整的，怎么到这里遍历就会经常漏掉呢？
		//感觉和一个方法里面循环没有多大区别，但是这样就百分百获取成功了。
		temp.put("normal", getPorts(normalPorts));
		temp.put("polling", getPorts(pickFromNormal));
		Set<SwitchPort> set=new HashSet<>(observePorts.keySet());
		set.removeAll(pickFromNormal);
		temp.put("observe", getPorts(set));
		temp.put("abnormal", getPorts(abnormalPorts));
		
		return temp;
	}
	
	public String getPorts(Collection<SwitchPort> ports){
		StringBuffer sb = new StringBuffer();
		for(SwitchPort port : ports) {
			sb.append(port.getSwitchDPID().toString() + "-" +port.getPort().getPortNumber() + ",");
		}
		if(!sb.toString().equals("")){
			sb.deleteCharAt(sb.lastIndexOf(","));
		}
		return sb.toString();
	}

	//切换方案
	@Override
	public synchronized void changePlanByRest(int flag) {
		STATUS = flag;
	}

	//返回入端口历史峰值
	@Override
	public Object showMaxTraffic() {
		Map<Integer, Double> map = new HashMap<>();
		for(Map.Entry<SwitchPort, U64> entry : inPortPacketsRes.entrySet()){
			SwitchPort sp = entry.getKey();
			if(rank.containsKey(sp)){
			//	double curIn = getOutPacketsByPort(sp)/(2.0 * flowStasInterval);
				double curIn = entry.getValue().getValue()/(1.0 * flowStasInterval);
				int terminatorNum = computeTerminatorNum(sp);
				map.put(terminatorNum, curIn);
			}
		}
		StringBuffer sb = new StringBuffer();
		sb.append(String.format("%-8s", "curIn:"));
		StringBuffer sb2 = new StringBuffer();
		sb2.append(String.format("%-8s", "maxIn:"));
		DecimalFormat df = new DecimalFormat("####0.00");
		for(Map.Entry<Integer, Double> entry : map.entrySet()){
			sb.append(String.format("%-12s", df.format(entry.getValue()) + "(" + entry.getKey() + ")"));
			sb2.append(String.format("%-12s", df.format(maxTraffics.get(entry.getKey())) + "(" + entry.getKey()  + ")"));
		}
		log.info("入流量、峰值比对：\r\n" + sb.toString() + "\r\n" + sb2.toString());
		
		return maxTraffics;
	}

	//更新入端口历史流量峰值，并写入maxTraffic文件
	@Override
	public synchronized void updateMaxTraffic() {
		for(Map.Entry<SwitchPort, U64> entry : inPortPacketsRes.entrySet()){
			SwitchPort sp = entry.getKey();
			if(rank.containsKey(sp)){
			//	double curIn = getOutPacketsByPort(sp)/(2.0 * flowStasInterval);
				double curIn = entry.getValue().getValue()/(1.0 * flowStasInterval);
				int terminatorNum = computeTerminatorNum(sp);
				if(curIn > maxTraffics.get(terminatorNum)){
					maxTraffics.put(terminatorNum, curIn);
				}
			}
		}
		StringBuffer sb = new StringBuffer();
		for(Map.Entry<Integer, Double> entry : maxTraffics.entrySet()){
			sb.append(entry.getKey() + " " + entry.getValue() + "\r\n");
		}
		log.info("======rest更新maxTraffic及峰值文件======" + "\r\n" + sb.toString());
		writeToTxt(filePath, false, sb.toString());
		
	}
	
	//计算交换机上的异常端口数 并判断是否有进一步动作
	private void countAbnormalPort(DatapathId dpid, boolean isAdd) {
		if (isAdd) {
			if(!abnormalPortsNum.containsKey(dpid)){
				abnormalPortsNum.put(dpid, 1);
			}else {
				abnormalPortsNum.put(dpid, abnormalPortsNum.get(dpid)+1);
				helpConvert(dpid);
			}
		} else {
			abnormalPortsNum.put(dpid, abnormalPortsNum.get(dpid)-1);
			helpConvert(dpid);
		}
		//计算后判断是否要转为静态
	}
	
	//判断验证规则是否要转换
	private void helpConvert(DatapathId dpid) {
		
		if(/*convertFlag.get(dpid)&&*/abnormalPortsNum.get(dpid)>portsInBind.get(dpid)/2) {
			if((System.currentTimeMillis()-stableTime)/1000<20) {
				//初始化网络时，网络状态很不稳定，定义一个初始化时间跳过这个阶段
				return ;
			}
			convertTable(dpid, true);
//			convertFlag.put(dpid, false);
			
		}else if(/*!convertFlag.get(dpid)&&*/abnormalPortsNum.get(dpid)<=portsInBind.get(dpid)/2) {
			convertTable(dpid, false);
//			convertFlag.put(dpid, true);
		}
		
	}

	//转为静态
	private void convertTable(DatapathId dpid, boolean toStatic) {
		
		if (toStatic) {
			List<Binding<?>> bindings=saviProvider.getBindings();
			Set<SwitchPort> switchPorts=new HashSet<>();
			for(Binding<?> binding : bindings) { 
				if(binding.getSwitchPort().getSwitchDPID().equals(dpid)) {
					switchPorts.add(binding.getSwitchPort());
				}
			}
			doFlowMod(switchPorts,STATIC_TABLE_ID);
			saviProvider.convertTable(dpid, true);
		} else {
			saviProvider.convertTable(dpid, false);
			
		}
	}
	
	protected int computeTerminatorNum(SwitchPort swport) {
//		int terminatorNum = (rank.size() / portsInBind.size()) * ((int)swport.getSwitchDPID().getLong() - (switchService.getAllSwitchDpids().size() - portsInBind.size()) - 1) + swport.getPort().getPortNumber() - 2;
//		if(!saviProvider.getHostWithPort().containsKey(swport)) {
//			log.warn("这个端口已经删除对应绑定表,移除端口集合");
//		}
		return saviProvider.getHostWithPort().get(swport);
	}
	
	@Override
	public void setPriorityLevel(int priorityLevel) {
		this.priorityLevel=priorityLevel;
	}
	
	@Override
	public Object getHostsCredit() {
		Map<Integer, Integer> map=new HashMap<>();
		for(Entry<SwitchPort, Integer> entry : hostsCredit.entrySet()) {
			int t=saviProvider.getHostWithPort().get(entry.getKey());
			map.put(t, entry.getValue()/8+1);
		}
		return map;
	}
	
	@Override
	public void setAutoCheck(boolean setAuto) {
		/*
		if (setAuto&&synAutoCheck) {
			checkRules.notify();
			synAutoCheck=false;
		} else if(!setAuto&&!synAutoCheck) {
			try {
				checkRules.wait();
				synAutoCheck=true;
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
		}
		*/
	}
	
	public void writeErrorLog(SwitchPort sp, boolean isAbnormal) {
		String text="";
		if (isAbnormal) {
			long lossNum=packetOfFlows.get(sp).getLossNum();
			if(pickFromNormal.contains(sp)) 
				lossNum=(long) (lossNum/0.28);
			text="端口："+"SwitchPort [switchDPID=" + sp.getSwitchDPID().toString() +
		               ", port=" + sp.getPort()+"  主机："+saviProvider.getHostWithPort().get(sp) + "发现异常---" + "攻击开始时间: "+sdflog.format(System.currentTimeMillis())
		               +"---发包："+(packetOfFlows.get(sp).getPassNum()+packetOfFlows.get(sp).getLossNum())+"  丢包率："+packetOfFlows.get(sp).getlossRate()
		               +"  丢包数："+packetOfFlows.get(sp).getLossNum();
		} else {
			text="端口："+"SwitchPort [switchDPID=" + sp.getSwitchDPID().toString() +
		               ", port=" + sp.getPort()+"  主机："+saviProvider.getHostWithPort().get(sp) + "恢复正常---" + "攻击结束时间: "+sdflog.format(System.currentTimeMillis())
		               +"---发包："+(packetOfFlows.get(sp).getPassNum()+packetOfFlows.get(sp).getLossNum())+"  丢包率："+packetOfFlows.get(sp).getlossRate()
		               +"  丢包数："+packetOfFlows.get(sp).getLossNum();
		}
		try {
			synchronized (filePath5) {
				File file =new File(filePath5);
				if(!file.exists()) {
					file.createNewFile();
					
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		BufferedWriter bw=null;
		try {
			bw = new BufferedWriter(new FileWriter(filePath5,true));
			bw.append(text);
			bw.newLine();
			bw.flush();
		} catch (IOException e) {
			e.printStackTrace();
		}finally {
			try {
				bw.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		
	}
	
}
