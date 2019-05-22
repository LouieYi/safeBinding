package net.floodlightcontroller.savi.module;

import com.sun.org.apache.xpath.internal.SourceTree;
import net.floodlightcontroller.accesscontrollist.ACL;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.util.SingletonTask;
import net.floodlightcontroller.devicemanager.SwitchPort;
import net.floodlightcontroller.packet.*;
import net.floodlightcontroller.routing.IRoutingDecision.RoutingAction;
import net.floodlightcontroller.savi.action.Action;
import net.floodlightcontroller.savi.action.Action.ActionFactory;
import net.floodlightcontroller.savi.binding.Binding;
import net.floodlightcontroller.savi.binding.BindingPool;
import net.floodlightcontroller.savi.binding.BindingStatus;
import org.projectfloodlight.openflow.protocol.OFFactories;
import org.projectfloodlight.openflow.protocol.OFVersion;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.*;

import javax.crypto.Mac;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class SafeBind extends SAVIBaseService {

    private static int TIMER_DELAY = 1; // 1s
    private static int UPDATE_DELAY = 2;

    //前两个字节掩码
    private static final IPv6Address MASK_HEAD=IPv6Address.of("ffff::ffff:ffff:ffff:0000");

    private static final IPv6Address LINKLOCAL=IPv6Address.of("fe80::200:ff:fe00:0");
    //控制器ip
    private static final IPv6Address CONTROLLER_IP=IPv6Address.of("fe80::6851:4d1a:5bab:b33f");
    //控制器mac
    private static final MacAddress CONTROLLER_MAC=MacAddress.of("00:50:56:c0:00:08");

    BindingPool<IPv6Address> pool;
    private Map<Integer, Binding<IPv6Address>> confirmQueue;
    private Map<Integer, Binding<IPv6Address>> requestQueue;
//    List<Binding<IPv6Address>> updateQueue;

    protected SingletonTask timer;
    private SingletonTask dadTimer;
    private SingletonTask detectionTimer;
    private SingletonTask nudTimer;

//    private Set<SwitchPort> dhcpStateless;      //无状态dhcp配置
    /*
    //交换机端口阈值
    private Map<SwitchPort, Integer> thresholds;
    //交换机端口异常次数
    private Map<SwitchPort, Integer> counts;
    //临时绑定表
    private ConcurrentSet<AuthTable> temporaryAuthTable=new ConcurrentSet<>();
    //dhcp 临时绑定表
    private ConcurrentHashMap<SwitchPort, AuthTable> tempAuthTable=new ConcurrentHashMap<>();
    */
    //主机探测集合
    private Map<SwitchPort, Long> detectionContainer = new ConcurrentHashMap<>();
    //dad检测时间
//    private final static long TENTATIVE_TIME=2000;

    @Override
    public boolean match(Ethernet eth) {
        if(eth.getEtherType() != EthType.IPv6)
            return false;
//        System.out.println(eth.getSourceMACAddress().toString());
//        System.out.println(eth.getDestinationMACAddress().toString());
        IPv6 iPv6= (IPv6) eth.getPayload();

        return isDHCPv6(iPv6)||isND(iPv6);
    }
    private boolean isDHCPv6(IPv6 iPv6){
        if(iPv6.getNextHeader().equals(IpProtocol.UDP)){
            UDP udp = (UDP)iPv6.getPayload();
            if(udp.getSourcePort().getPort() == 546 || udp.getDestinationPort().getPort() == 546){
                return true;
            }
        }
        return false;
    }

    private boolean isND(IPv6 ipv6){
        if(ipv6.getNextHeader().equals(IpProtocol.IPv6_ICMP)){
            ICMPv6 icmpv6 = (ICMPv6)ipv6.getPayload();
            byte type = icmpv6.getICMPv6Type();
            return type== ICMPv6.ROUTER_SOLICITATION||
                    type== ICMPv6.ROUTER_ADVERTSEMENT||
                    type== ICMPv6.NEIGHBOR_SOLICITATION||
                    type== ICMPv6.NEIGHBOR_ADVERTISEMENT;
        }
        return false;
    }

    @Override
    public List<Match> getMatches() {
        List<Match> array = new ArrayList<>();

//        OFVersion ofVersion=switchService.getSwitch(DatapathId.of(1)).getOFFactory().getVersion();
        
        Match.Builder mb = OFFactories.getFactory(OFVersion.OF_14).buildMatch();

        mb.setExact(MatchField.ETH_TYPE, EthType.IPv6);
        mb.setExact(MatchField.IP_PROTO, IpProtocol.UDP);
        mb.setExact(MatchField.UDP_DST, TransportPort.of(547));
        mb.setExact(MatchField.UDP_SRC, TransportPort.of(546));
        array.add(mb.build());

        mb = OFFactories.getFactory(OFVersion.OF_14).buildMatch();
        mb.setExact(MatchField.ETH_TYPE, EthType.IPv6);
        mb.setExact(MatchField.IP_PROTO, IpProtocol.UDP);
        mb.setExact(MatchField.UDP_DST, TransportPort.of(546));
        mb.setExact(MatchField.UDP_SRC, TransportPort.of(547));
        array.add(mb.build());

        Match.Builder mb2 = OFFactories.getFactory(OFVersion.OF_14).buildMatch();

//         //echo request 探测主机是否在线
//        mb2.setExact(MatchField.ETH_TYPE, EthType.IPv6);
//        mb2.setExact(MatchField.IP_PROTO, IpProtocol.IPv6_ICMP);
//        mb2.setExact(MatchField.ICMPV6_TYPE, U8.of((byte) 129));
//        array.add(mb2.build());

        /*
         * RS消息不用处理
        mb2.setExact(MatchField.ETH_TYPE, EthType.IPv6);
        mb2.setExact(MatchField.IP_PROTO, IpProtocol.IPv6_ICMP);
        mb2.setExact(MatchField.ICMPV6_TYPE, U8.of((byte) 133));
        array.add(mb2.build());
        */

        //RA
        mb2.setExact(MatchField.ETH_TYPE, EthType.IPv6);
        mb2.setExact(MatchField.IP_PROTO, IpProtocol.IPv6_ICMP);
        mb2.setExact(MatchField.ICMPV6_TYPE, U8.of((byte) 134));
        array.add(mb2.build());

        //DAD NA
        mb2.setExact(MatchField.ICMPV6_TYPE, U8.of((byte) 136));
        mb2.setExact(MatchField.IPV6_DST, IPv6Address.of("ff02::1"));
        array.add(mb2.build());
        //NUD NA
        mb2.setExact(MatchField.IPV6_DST, CONTROLLER_IP);
        array.add(mb2.build());

        //NS 加个ff02::/16 前缀匹配
        mb2.setExact(MatchField.IPV6_SRC, IPv6Address.NONE);
        mb2.setMasked(MatchField.IPV6_DST, IPv6Address.of("ff02::"),IPv6Address.of("ffff::"));
        mb2.setExact(MatchField.ICMPV6_TYPE, U8.of((byte) 135));
        array.add(mb2.build());

        return array;
    }

    @Override
    public RoutingAction process(SwitchPort switchPort, Ethernet eth) {
        IPv6 ipv6= (IPv6) eth.getPayload();
        MacAddress macAddress=eth.getSourceMACAddress();
        if(isDHCPv6(ipv6)){

            //非边缘交换机端口收到 即边缘交换机转发过来的--->不做处理---->转发 同理-->抽风了
//            if (!topologyService.isEdge(switchPort.getSwitchDPID(), switchPort.getPort())) {
//                return RoutingAction.FORWARD_OR_FLOOD;
//            }
            if (switchPort.getSwitchDPID().getLong() < 5 && switchPort.getPort().getShortPortNumber() < 3) {
                return processDHCPv6(switchPort, macAddress, eth);
            }
            return RoutingAction.FORWARD_OR_FLOOD;

        }else if(isND(ipv6)) {
            ICMPv6 icmPv6= (ICMPv6) ipv6.getPayload();
            //非边缘交换机端口收到 即边缘交换机转发过来的--->不做处理---->转发
            if(icmPv6.getICMPv6Type() ==ICMPv6.ROUTER_ADVERTSEMENT){
                return processRouterAdvertisement(switchPort, icmPv6);
            }
            //控制器抽风了 不是边缘交换机端口的都是 真是...
//            if (topologyService.isEdge(switchPort.getSwitchDPID(), switchPort.getPort())) {
//                return processND(switchPort, macAddress, ipv6);
//            }
            if (switchPort.getSwitchDPID().getLong() < 5 && switchPort.getPort().getShortPortNumber() < 3) {
                return processND(switchPort, macAddress, ipv6);
            }
            return RoutingAction.FORWARD_OR_FLOOD;
        }else {
            return RoutingAction.FORWARD_OR_FLOOD;
        }
    }

    @Override
    public void handlePortDown(SwitchPort switchPort) {
        if (detectionContainer.containsKey(switchPort)) {
            detectionContainer.remove(switchPort);
        }
        List<Action> actions=new ArrayList<>();
        List<Binding<IPv6Address>> bindings;
        synchronized (bindingMap) {
            bindings = bindingMap.remove(switchPort);
        }
        if(bindings==null) {
            return;
        }

        updateLog((byte)0, bindings.get(0).getMacAddress(), switchPort, null);

        for(Binding<IPv6Address> binding : bindings){
            pool.delBinding(binding.getAddress());
            System.out.println("==========Port Down==========");
            actions.add(Action.ActionFactory.getUnbindIPv6Action(binding.getAddress(),binding));
        }
        saviProvider.pushActions(actions);
    }

    private void updateLog(byte type, MacAddress macAddress, SwitchPort switchPort, IPv6Address iPv6Address){
        StringBuilder sb=new StringBuilder();
        sb.append("=====更新日志======");
        switch(type){
            case 0:
                sb.append("\n发现主机离线，SwitchPort：s");
                sb.append(switchPort.getSwitchDPID().getLong()).append(", ");
                sb.append(switchPort.getPort().getPortNumber());
                break;
            case 1:
                sb.append("\n发现IP地址失效，IP：");
                sb.append(iPv6Address.toString());
                break;
            default:
                break;
        }
        sb.append("\n对应主机MAC：");
        sb.append(macAddress.toString());
        System.out.println(sb.toString());
    }

    private RoutingAction processND(SwitchPort switchPort, MacAddress macAddress, IPv6 ipv6){
        ICMPv6 icmPv6= (ICMPv6) ipv6.getPayload();
        IPv6Address sourceAddress=ipv6.getSourceAddress();

        switch(icmPv6.getICMPv6Type()){
            case ICMPv6.NEIGHBOR_SOLICITATION:
                return processNeighborSolicit(switchPort, ipv6, sourceAddress, macAddress);
            case ICMPv6.NEIGHBOR_ADVERTISEMENT:
                return processNeighborAdvertisement(switchPort, ipv6, sourceAddress, macAddress);
            default :
            	return RoutingAction.FORWARD_OR_FLOOD;
        }
    }

    private RoutingAction processRouterAdvertisement(SwitchPort switchPort, ICMPv6 icmPv6){
        //这里交换机认为是边缘端口 搁置
//        if (topologyService.isEdge(switchPort.getSwitchDPID(), switchPort.getPort())) {
//            handleException(switchPort,"路由通告消息",null);
//            return RoutingAction.NONE;
//        }
        if (switchPort.getSwitchDPID().getLong() < 5 && switchPort.getPort().getShortPortNumber() < 3) {
            handleException(switchPort,"路由通告消息",null);
            return RoutingAction.NONE;
        }
        DatapathId dpid=switchPort.getSwitchDPID();
        IOFSwitch sw=switchService.getSwitch(dpid);

        for(OFPort port : sw.getEnabledPortNumbers()){
            SwitchPort temp=new SwitchPort(dpid, port);
//            if (topologyService.isEdge(dpid, port)) {
            //if (topologyService.isEdge(dpid, port)&&(dpid.getLong!=5||dpid.getLong!=6)&&port.getShortPortNumber()!=3) {   //去掉ra的交换机入端口就好了
            System.out.println("*****判断之前*****"+dpid.getLong()+", "+port.getPortNumber());
            if (dpid.getLong()<5&&port.getShortPortNumber()<3) {
                System.out.println("*****判断之hou*****"+dpid.getLong()+", "+port.getPortNumber());
                if (icmPv6.isManagedAddressConfiguration()) {
                    dhcpInfo.add(temp);
                }else {
                    for(ICMPv6Option icmPv6Option : icmPv6.getOptions()){
                        if (icmPv6Option.getCode() == 3) {
                            if (!prefixInfo.containsKey(temp)) {
                                prefixInfo.put(temp, new ArrayList<ICMPv6Option>());
                            }
                            prefixInfo.get(temp).add(icmPv6Option);

                            //更新时间
                            List<Binding<IPv6Address>> bindings=bindingMap.get(temp);
                            if (bindings != null && bindings.size() > 1) {
                                System.out.println("SLAAC配置地址后 收到RA");
                                IPv6Address addressMask=getIPv6AddressMask(icmPv6Option);
                                for(Binding<IPv6Address> binding : bindings){
                                    if(binding.getType()==0)
                                        continue;
                                    if (binding.getAddress().applyMask(addressMask)
                                            .equals(icmPv6Option.getPrefixAddress().applyMask(addressMask))) {
                                        System.out.println("RA更新有效时间");
                                        binding.setLeaseTime((System.currentTimeMillis())/1000+icmPv6Option.getValidLifetime());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        for(SwitchPort switchPort1:prefixInfo.keySet()){
            System.out.println(switchPort1.getSwitchDPID().getLong()+", "+switchPort1.getPort().getPortNumber()
            +prefixInfo.get(switchPort1).get(0).getPrefixAddress().toString());
        }

        return RoutingAction.FORWARD_OR_FLOOD;
    }

    private RoutingAction processNeighborSolicit(SwitchPort switchPort, IPv6 iPv6,
                                                 IPv6Address sourceAddress, MacAddress macAddress){
        ICMPv6 icmPv6= (ICMPv6) iPv6.getPayload();

//    	System.out.println("处理NS");
        if (sourceAddress.isUnspecified()) {      //源地址为::
//        	System.out.println("NS未指定地址");
            IPv6Address targetAddress=icmPv6.getTargetAddress();

            //本地链路DAD
            if (targetAddress.applyMask(MASK_HEAD).equals(LINKLOCAL)) {
                //本地链路地址已经存在，判断原主机是否响应
                //*************************************************//
                if (bindingMap.containsKey(switchPort)) {
                    Binding<IPv6Address> linkLocal=null;
                    for(Binding<IPv6Address> binding : bindingMap.get(switchPort)){
                        if (binding.getType() == 0) {
                            linkLocal=binding;
                            break;
                        }
                    }
                    if (linkLocal!=null&&macAddress.equals(linkLocal.getMacAddress())) {
                        if (!linkLocal.getAddress().equals(targetAddress)) {
                            System.out.println("325");
                            handleException(switchPort, "邻居请求消息NS",linkLocal.getAddress());
                            return RoutingAction.NONE;
                        }
                        System.out.println("原主机再次发送的同份NS");
                        return RoutingAction.FORWARD_OR_FLOOD;
                    }
                    if(linkLocal!=null){
                        sendDetectionMessage(linkLocal);
                        formerHost.add(switchPort);
                    }
                }

                //没问题后 建立验证表
                Binding<IPv6Address> binding=new Binding<>();
                binding.setAddress(targetAddress);
                binding.setType((byte)0);
                binding.setMacAddress(macAddress);
                binding.setSwitchPort(switchPort);
                binding.setBindingTime();

                return handleDAD(binding);

            }else {     //绑定表已经有fe80的地址了 全局链路DAD

                // 本地链路地址没有配置 这个概率太低了
                // 或者
                // mac地址不对
                List<Binding<IPv6Address>> bindings=bindingMap.get(switchPort);
//                if ( bindings == null || bindings.isEmpty()) {
//                    if (!fixBug.containsKey(switchPort)) {
//                        handleException(switchPort,"邻居请求消息NS",targetAddress);
//                        return RoutingAction.NONE;
//                    }
//                }
                if (bindings!=null&&!bindings.get(0).getMacAddress().equals(macAddress)) {
                    handleException(switchPort, "邻居请求消息NS",targetAddress);
                    return RoutingAction.NONE;
                }
                //同份的NS可以直接转发
                if (pool.check(targetAddress, macAddress, switchPort)) {
                    return RoutingAction.FORWARD_OR_FLOOD;
                }
                // 本地链路成功之后...

                //DHCPv6端口集合
                if(!prefixInfo.containsKey(switchPort)){
                    if (dhcpPorts.contains(switchPort)) {
                        Binding<IPv6Address> bind=new Binding<>();
                        bind.setAddress(targetAddress);
                        bind.setMacAddress(macAddress);
                        bind.setSwitchPort(switchPort);
                        bind.setType((byte)1);  //默认公网地址  后面判断是不是 临时地址的话就修改成2
                        bind.setBindingTime();
                        return handleDAD(bind);
                    }
                    System.out.println("DHCPv6端口集合");
                    if (dhcpPorts.contains(switchPort)) {
                        return RoutingAction.FORWARD_OR_FLOOD;
                    }
                    //用replyQueue代替了验证表中对应的IP地址信息 可以重构
                    if (!replyQueue.containsKey(switchPort)) {
                        System.out.println("386");
                        handleException(switchPort, "邻居请求消息NS",targetAddress);
                        return RoutingAction.NONE;
                    }
                    Binding<IPv6Address> binding=replyQueue.remove(switchPort);
                    if (binding.getAddress().equals(targetAddress)&&binding.getMacAddress().equals(macAddress)) {
                        dadContainer.add(binding);
                        return RoutingAction.FORWARD_OR_FLOOD;
                    }
                    handleException(switchPort, "邻居请求消息NS", targetAddress);
                    return RoutingAction.NONE;
                }

                Binding<IPv6Address> bind=new Binding<>();
                bind.setAddress(targetAddress);
                bind.setMacAddress(macAddress);
                bind.setSwitchPort(switchPort);
                //默认公网地址  后面判断是不是 临时地址的话就修改成2   -->暂时无需记录是否是临时地址。可以保留，临时地址有效时间与非临时地址不一样，留作扩展
                bind.setType((byte)1);
                bind.setBindingTime();

                List<ICMPv6Option> list=prefixInfo.get(switchPort);
                ICMPv6Option icmPv6Option=null;
                for(ICMPv6Option option : list) {
                    IPv6Address addressMask = getIPv6AddressMask(option);
                    if (targetAddress.applyMask(addressMask).equals(option.getPrefixAddress().applyMask(addressMask))) {
                        icmPv6Option=option;
                    }
                }
                //没有匹配的前缀
                if (icmPv6Option == null) {
                    System.out.println("没有匹配的前缀367");
                    handleException(switchPort,"邻居请求报文NS",targetAddress);
                    return RoutingAction.NONE;
                }
                IPv6Address addressMask=getIPv6AddressMask(icmPv6Option);

                //***********************以下是临时地址************************//
                if (targetAddress.applyMask(IPv6Address.of("0::ffff:fff0")).equals(IPv6Address.of("0::fe00:0"))) {
                    bind.setType((byte) 2);
                }
                //***********************以上是临时地址************************//
                //临时地址和非临时地址一起处理
                if (bindings != null) {
                    for(Binding<IPv6Address> binding : bindings){
                        if(binding.getType()!=bind.getType()) {
                            continue;
                        }
                        if (binding.getAddress().applyMask(addressMask)
                                .equals(icmPv6Option.getPrefixAddress().applyMask(addressMask))) {
                            //这个前缀已经绑定公网地址
                            System.out.println("前缀已有绑定448");
                            handleException(switchPort, "邻居请求消息NS", targetAddress);
                            return RoutingAction.NONE;
                        }
                    }
                }
                //传不转发看情况
                bind.setLeaseTime(System.currentTimeMillis()/1000+icmPv6Option.getValidLifetime());
                return handleDAD(bind);
            }
        }else{      //不是DAD检测
            if(check(switchPort, macAddress, sourceAddress)){
                if(iPv6.getDestinationAddress().equals(CONTROLLER_IP)){
                    Binding<IPv6Address> dstBind=new Binding<>();
                    dstBind.setAddress(sourceAddress);
                    dstBind.setMacAddress(macAddress);
                    dstBind.setSwitchPort(switchPort);
                    sendNAMessage(srcBind, dstBind);
                    return RoutingAction.NONE;
                }
                return RoutingAction.FORWARD_OR_FLOOD;
            }else{
                handleException(switchPort, "邻居请求消息NS", sourceAddress);
                log.error("应该不会发生，这部分NS是通过验证规则的，然后经过转发表的table_miss进来的");
                return RoutingAction.NONE;
            }
        }
    }

    private IPv6Address getIPv6AddressMask(ICMPv6Option option){
        byte prefixLen=option.getPrefixLength();
        //生成前缀掩码
        byte[] mask=new byte[16];
        int m=prefixLen/8;
        int n=prefixLen%8;
        for(int i=0;i<m;i++){
            mask[i]=(byte)0xff;
        }
        mask[m]=(byte)(0xff>>(8-n));
        return IPv6Address.of(mask);
    }

    //在DAD检测的时候一次性发多个ns --> 预防
    // fe80 --> type=0
    // global unicast ip type=1
    // new ip type=2
    private RoutingAction handleDAD(Binding<IPv6Address> binding){

        synchronized (dadContainer) {

            for (Binding<IPv6Address> bind : dadContainer) {
                if (bind.getAddress().equals(binding.getAddress())
                        &&(!bind.getMacAddress().equals(binding.getMacAddress())
                        ||!bind.getSwitchPort().equals(binding.getSwitchPort()))) {
                    //sendNA src, dst
                    sendNAMessage(bind, binding);
                    return RoutingAction.NONE;
                }
            }
            dadContainer.add(binding);
        }

        //不在DAD容器里的地址，由主机自己来发送NA
        return RoutingAction.FORWARD_OR_FLOOD;
    }

    private RoutingAction processNeighborAdvertisement(SwitchPort switchPort, IPv6 iPv6
            , IPv6Address sourceAddress, MacAddress macAddress){
        ICMPv6 icmPv6= (ICMPv6) iPv6.getPayload();
        IPv6Address targetAddress=icmPv6.getTargetAddress();
        //源地址不匹配单播地址也不匹配链路地址或者和目标地址不一致
        if((!check(switchPort, macAddress, sourceAddress)) ||!targetAddress.equals(sourceAddress)){

            handleException(switchPort, "邻居通告消息NA", targetAddress);
            return RoutingAction.NONE;
        }

        IPv6Address destinationAddress=iPv6.getDestinationAddress();
        if (icmPv6.isSolicitedFlag()&&destinationAddress.equals(IPv6Address.of("ff02::1"))/*toString().matches("^ff02::\\.\\*")*/) {
            handleDAD(icmPv6);
            return RoutingAction.FORWARD_OR_FLOOD;
        }
        //控制器ip  这里是处理探测原主机是否在线收到的NA包 --> 在线主机
//        System.out.println("============收到NA,目的地址是"+destinationAddress.toString());
        if(destinationAddress.equals(CONTROLLER_IP)){
            synchronized (detectionContainer){
                detectionContainer.remove(switchPort);
                formerHost.remove(switchPort);
            }
            return RoutingAction.NONE;
        }
        return RoutingAction.FORWARD_OR_FLOOD;
    }

    // 处理DAD的NA报文
    private void handleDAD(ICMPv6 icmPv6){
        IPv6Address targetAddress=icmPv6.getTargetAddress();
        synchronized (dadContainer){
            Iterator<Binding<IPv6Address>> iter=dadContainer.iterator();
            while (iter.hasNext()) {
                Binding<IPv6Address> binding=iter.next();
                if (binding.getAddress().equals(targetAddress)) {
                    iter.remove();
                    break;
                }
            }
        }
    }

    private RoutingAction processDHCPv6(SwitchPort switchPort, MacAddress macAddress, Ethernet eth){
        IPv6 iPv6= (IPv6) eth.getPayload();
        UDP udp = (UDP)iPv6.getPayload();
        DHCPv6 dhcp = (DHCPv6)udp.getPayload();
        if (dhcpPorts.isEmpty()||dhcpPorts.contains(switchPort)) {
            switch(dhcp.getMessageType()){
                case ADVERTISE:
                    return processAdvertise(switchPort, eth);
                case REPLY:
                    return processReply(switchPort, eth);
                case RECONFIGURE:
                    return RoutingAction.FORWARD_OR_FLOOD;
                default:
                    return RoutingAction.FORWARD_OR_FLOOD;
            }
        }else {
            //来自非dhcp配置的主机集合的
            if(!dhcpInfo.contains(switchPort)){
                handleException(switchPort, dhcp.getMessageType().toString(),dhcp.getTargetAddress());
                return RoutingAction.NONE;
            }
            switch(dhcp.getMessageType()){
                case SOLICIT:
                    return processSolicit(switchPort, macAddress, iPv6);
                case REQUEST:
                    return processRequest(switchPort, macAddress, iPv6);
                case CONFIRM:
                    return processConfirm(switchPort, macAddress, iPv6);
                case RENEW:
                    return processRenew(switchPort, macAddress, iPv6);
                case REBIND:
                    return processRebind(switchPort, macAddress, iPv6);
                case RELEASE:
                    return processRelease(switchPort, macAddress, iPv6);
                case DECLINE:
                    return processDecline(switchPort, macAddress, iPv6);
                case INFORMATION_REQUEST:
                    return RoutingAction.FORWARD_OR_FLOOD;
                default:
                    handleException(switchPort, "DHCPv6服务端消息", null);
                    return RoutingAction.NONE;
            }
        }
    }

    private RoutingAction processSolicit(SwitchPort switchPort, MacAddress macAddress, IPv6 iPv6){
        //检查源地址和mac地址
        log.info("==============="+iPv6.getSourceAddress().toString()+"===============");
        if(!check(switchPort, macAddress, iPv6.getSourceAddress())){
            handleException(switchPort, "Solicit", iPv6.getSourceAddress());
            return RoutingAction.NONE;
        }

        return RoutingAction.FORWARD_OR_FLOOD;
    }

    private RoutingAction processAdvertise(SwitchPort switchPort,Ethernet eth){
        List<Action> actions = new ArrayList<>();
        IPv6 ipv6 = (IPv6)eth.getPayload();
        UDP udp = (UDP)ipv6.getPayload();
        DHCPv6 dhcpv6 = (DHCPv6)udp.getPayload();
        MacAddress srcMac = eth.getSourceMACAddress();
        IPv6Address ipv6Address = ipv6.getSourceAddress();
        int id = dhcpv6.getTransactionId();
        log.info("ADV "+id);

//        //绑定dhcp服务器
//        if(!pool.isContain(ipv6Address)){
//            Binding<IPv6Address> binding = new Binding<>();
//
//            binding.setAddress(ipv6Address);
//            binding.setSwitchPort(switchPort);
//            binding.setMacAddress(srcMac);
//            binding.setStatus(BindingStatus.BOUND);
//            binding.setAddress(ipv6Address);
//            pool.addBinding(ipv6Address, binding);
//
//            actions.add(ActionFactory.getBindIPv6Action(binding));
//        }
//
//        actions.add(ActionFactory.getFloodAction(switchPort.getSwitchDPID(), switchPort.getPort(), eth));
//        saviProvider.pushActions(actions);
        return RoutingAction.FORWARD_OR_FLOOD;
    }

    private RoutingAction processRequest(SwitchPort switchPort, MacAddress macAddress, IPv6 iPv6){
        if(!check(switchPort, macAddress, iPv6.getSourceAddress())){
            handleException(switchPort, "Request", iPv6.getSourceAddress());
            return RoutingAction.NONE;
        }

        UDP udp = (UDP)iPv6.getPayload();
        DHCPv6 dhcpv6 = (DHCPv6)udp.getPayload();
        IPv6Address ipv6Address = dhcpv6.getTargetAddress();
        Binding<IPv6Address> binding = new Binding<>();
        int id = dhcpv6.getTransactionId();
        log.info("REQUEST "+id);

        binding.setAddress(ipv6Address);
        binding.setStatus(BindingStatus.REQUESTING);
        binding.setMacAddress(macAddress);
        binding.setTransactionId(dhcpv6.getTransactionId());
        binding.setSwitchPort(switchPort);
        binding.setStatus(BindingStatus.REQUESTING);

        System.out.println("===========Request id"+id+"===========");
        requestQueue.put(id, binding);

        return RoutingAction.FORWARD_OR_FLOOD;
    }

    private RoutingAction processReply(SwitchPort switchPort,Ethernet eth){

        System.out.println("收到Reply");
        List<Action> actions = new ArrayList<>();
        IPv6 ipv6 = (IPv6)eth.getPayload();
        UDP udp = (UDP)ipv6.getPayload();
        DHCPv6 dhcpv6 = (DHCPv6)udp.getPayload();
        IPv6Address ipv6Address = dhcpv6.getTargetAddress();
        MacAddress macAddress = eth.getDestinationMACAddress();
        int id = dhcpv6.getTransactionId();

        System.out.println("===========Reply id"+id+"===========");
        log.info("REPLY");

        if(confirmQueue.containsKey(id)){
            Binding<IPv6Address> binding = confirmQueue.get(id);
            if (binding.getStatus() != BindingStatus.CONFIRMING) {
                handleException(switchPort,"",null);
                return RoutingAction.NONE;
            }
            binding.setStatus(BindingStatus.DETECTING);
            binding.setType((byte)1);

            confirmQueue.remove(id);
            synchronized (replyQueue){
                replyQueue.put(binding.getSwitchPort(), binding);
            }

        }else if(requestQueue.containsKey(id)) {
            System.out.println("+++++++++++++处理Request Reply++++++++++++");
            Binding<IPv6Address> binding = requestQueue.get(id);

            if (binding.getStatus() == BindingStatus.REQUESTING) {
                binding.setStatus(BindingStatus.DETECTING);
                binding.setLeaseTime(dhcpv6.getValidLifetime()+(System.currentTimeMillis())/1000);
                binding.setBindingTime();
                binding.setType((byte)1);
            }else{
                handleException(switchPort,"",null);
                return RoutingAction.NONE;
            }

            requestQueue.remove(id);
            synchronized (replyQueue){
                replyQueue.put(binding.getSwitchPort(), binding);
            }

        }else if(pool.isContain(ipv6Address)){
            Binding<IPv6Address> binding = pool.getBinding(ipv6Address);
            if(binding.getStatus() == BindingStatus.RENEWING
                    ||binding.getStatus() == BindingStatus.REBINDING){
                binding.setStatus(BindingStatus.BOUND);
                long now=System.currentTimeMillis()/1000;
                binding.setLeaseTime(now+dhcpv6.getValidLifetime());
                binding.setBindingTime();

                for(Binding<IPv6Address> bind : bindingMap.get(switchPort)){
                    if (bind.getAddress().equals(ipv6Address)) {
                        bind.setLeaseTime(now+dhcpv6.getValidLifetime());
                        break;
                    }
                }
            }
        }
        return RoutingAction.FORWARD_OR_FLOOD;
    }

    private RoutingAction processConfirm(SwitchPort switchPort, MacAddress macAddress, IPv6 iPv6){
        UDP udp = (UDP)iPv6.getPayload();
        DHCPv6 dhcpv6 = (DHCPv6)udp.getPayload();
        IPv6Address ipv6Address = dhcpv6.getTargetAddress();
        IPv6Address sourceAddress=iPv6.getSourceAddress();

        //该端口未绑定且不匹配  --> 异常
        if (!bindingMap.containsKey(switchPort) || !check(switchPort, macAddress, sourceAddress)) {
            handleException(switchPort,"Confirm", sourceAddress);
            return RoutingAction.NONE;
        }


        //该端口未绑定 --> 主机位置发生迁移 或者回到原端口
        /*if(pool.check(ipv6Address, macAddress, switchPort)){
            Binding<IPv6Address> binding = pool.getBinding(ipv6Address);
            binding.setStatus(BindingStatus.CONFIRMING);
            confirmQueue.put(Integer.valueOf(dhcpv6.getTransactionId()), binding);
        }*/
        Binding<IPv6Address> binding = new Binding<>();
        binding.setAddress(ipv6Address);
        binding.setStatus(BindingStatus.CONFIRMING);
        binding.setMacAddress(macAddress);
        binding.setTransactionId(dhcpv6.getTransactionId());
        binding.setSwitchPort(switchPort);
        confirmQueue.put(Integer.valueOf(dhcpv6.getTransactionId()), binding);
        return RoutingAction.FORWARD_OR_FLOOD;
    }

    protected RoutingAction processRenew(SwitchPort switchPort, MacAddress macAddress, IPv6 iPv6){
        return processRebind(switchPort, macAddress, iPv6);
    }

    private RoutingAction processRebind(SwitchPort switchPort, MacAddress macAddress, IPv6 iPv6){
        UDP udp = (UDP)iPv6.getPayload();
        DHCPv6 dhcpv6 = (DHCPv6)udp.getPayload();
        IPv6Address ipv6Address = dhcpv6.getTargetAddress();
        IPv6Address sourceAddress=iPv6.getSourceAddress();
        if(!check(switchPort, macAddress, ipv6Address)||!check(switchPort, macAddress, sourceAddress)){
            handleException(switchPort, "Rebind", ipv6Address);
            return RoutingAction.NONE;
        }
        Binding<IPv6Address> binding=pool.getBinding(ipv6Address);
        binding.setStatus(BindingStatus.RENEWING);

        return RoutingAction.FORWARD_OR_FLOOD;
    }

    private RoutingAction processRelease(SwitchPort switchPort, MacAddress macAddress, IPv6 iPv6){
        UDP udp = (UDP)iPv6.getPayload();
        DHCPv6 dhcpv6 = (DHCPv6)udp.getPayload();
        IPv6Address ipv6Address = dhcpv6.getTargetAddress();
        IPv6Address sourceAddress=iPv6.getSourceAddress();
        if (!check(switchPort, macAddress, ipv6Address) || !check(switchPort, macAddress, sourceAddress)) {
            handleException(switchPort, "Release", ipv6Address);
            return RoutingAction.NONE;
        }
        //从绑定表和验证表中删除
        Binding<IPv6Address> binding=pool.getBinding(ipv6Address);
        pool.delBinding(ipv6Address);
        Iterator<Binding<IPv6Address>> iter=bindingMap.get(switchPort).iterator();
        while (iter.hasNext()) {
            Binding<IPv6Address> bind=iter.next();
            if(bind.getMacAddress().equals(macAddress)
                    &&bind.getSwitchPort().equals(switchPort)
                    &&bind.getAddress().equals(ipv6Address)){
                iter.remove();
                break;
            }

        }
        List<Action> actions=new ArrayList<>();
        System.out.println("========release=========");
        actions.add(ActionFactory.getUnbindIPv6Action(ipv6Address, binding));
        saviProvider.pushActions(actions);
        return RoutingAction.FORWARD_OR_FLOOD;
    }

    private RoutingAction processDecline(SwitchPort switchPort, MacAddress macAddress, IPv6 iPv6){
        return processRelease(switchPort, macAddress, iPv6);
    }

    private void handleException(SwitchPort switchPort, String string, IPv6Address iPv6Address){
        StringBuilder sb=new StringBuilder();
        sb.append("\n=====异常日志======");
        sb.append("\n发现伪造包的交换机端口：s");
        sb.append(switchPort.getSwitchDPID().getLong());
        sb.append("，");
        sb.append(switchPort.getPort().getShortPortNumber());
        if(bindingMap.get(switchPort)!=null&&bindingMap.get(switchPort).size()!=0){
            sb.append("\n对应主机MAC地址：");
            sb.append(bindingMap.get(switchPort).get(0).getMacAddress().toString());
        }
//        if (forgeAddress != null) {
//            sb.append("\n伪造的MAC地址：");
//            sb.append(forgeAddress.toString());
//        }
        sb.append("\n伪造的消息类型:");
        sb.append(string);
        if (iPv6Address != null) {
            sb.append("  伪造的IP：");
            sb.append(iPv6Address.toString());
        }
        log.info(sb.toString());
    }

    private boolean check(SwitchPort switchPort, MacAddress macAddress, IPv6Address iPv6Address){
//        return pool.check(iPv6Address, macAddress, switchPort);
        List<Action> actions=new ArrayList<>();
        actions.add(ActionFactory.getCheckIPv6Binding(switchPort,macAddress,iPv6Address));
        return saviProvider.pushActions(actions);
    }

    @Override
    public void checkDeadline() {
        List<Action> actions = new ArrayList<>();
        for(Binding<IPv6Address> binding:pool.getAllBindings()){
            if(binding.isLeaseExpired()){
                pool.delBinding(binding.getAddress());
                updateLog((byte)1, binding.getMacAddress(), null, binding.getAddress());
                if(binding.getStatus()==BindingStatus.BOUND) {
                    System.out.println("=========IP失效==========");
                    actions.add(Action.ActionFactory.getUnbindIPv6Action(binding.getAddress(), binding));
                    List<Binding<IPv6Address>> list= bindingMap.get(binding.getSwitchPort());
                    if (list != null) {
                        synchronized (list){
                            for(Binding<IPv6Address> bind : list){
                                if(bind.getType()==0)
                                    continue;
                                if(bind.getAddress().equals(binding.getAddress()))
                                    list.remove(bind);
                            }
                        }
                    }
                }
            }
            //总的地址 减去公网地址 减去本地链路地址 即为临时地址
            long now=System.currentTimeMillis()/1000;
            if(binding.getAddress().equals(IPv6Address.of("2001:db1::200:ff:fe00:2"))){
                writeToTxt(binding.getLeaseTime()-now);
            }else if(binding.getAddress().equals(IPv6Address.of("2001:db8:0:1::200"))){
                writeToTxt(binding.getLeaseTime()-now);
            }
        }
        if(actions.size()>0){
            saviProvider.pushActions(actions);
        }
    }

    @Override
    public void startUpService() {
        pool = new BindingPool<>();

        confirmQueue = new HashMap<>();
        requestQueue = new HashMap<>();

        ScheduledExecutorService ses = threadPoolService.getScheduledExecutor();


        //检查主机是否在线
        timer = new SingletonTask(ses, new Runnable() {
            @Override
            public void run() {
                long tmp=System.currentTimeMillis();
                synchronized (detectionContainer) {
                    for(Map.Entry<SwitchPort, Long> entry : detectionContainer.entrySet()){
                        //没有收到NA
                        if((tmp-entry.getValue())/1000>UPDATE_DELAY){

                            List<Action> actions=new ArrayList<>();
                            for(Binding<IPv6Address> binding : bindingMap.remove(entry.getKey())){
                                IPv6Address iPv6Address=binding.getAddress();
                                System.out.println("==========NUD未响应=========");
                                actions.add(ActionFactory.getUnbindIPv6Action(iPv6Address, pool.getBinding(iPv6Address)));
                                pool.delBinding(iPv6Address);
                            }

                            saviProvider.pushActions(actions);
                            detectionContainer.remove(entry.getKey());
                        }
                    }
                }
                timer.reschedule(TIMER_DELAY, TimeUnit.SECONDS);
            }
        });
        timer.reschedule(12, TimeUnit.SECONDS);


        //dad处理模块
        ScheduledExecutorService dses = threadPoolService.getScheduledExecutor();
        dadTimer=new SingletonTask(dses, new Runnable() {
            @Override
            public void run() {

                synchronized (dadContainer){
                    long now=System.currentTimeMillis()/1000;
                    for(Binding<IPv6Address> binding : dadContainer){
                        if (now - binding.getBindingTime() > UPDATE_DELAY) {
                            //对新主机：原主机是否在线还不知道 只能跳过
                            if (formerHost.contains(binding.getSwitchPort())) {
                                continue;
                            }
                            binding.setStatus(BindingStatus.BOUND);
                            pool.addBinding(binding.getAddress(), binding);

                            List<Binding<IPv6Address>> list=bindingMap.get(binding.getSwitchPort());
                            if (list == null) {
                                list=new CopyOnWriteArrayList<>();
                                bindingMap.put(binding.getSwitchPort(), list);
                            }
                            list.add(binding);

                            dadContainer.remove(binding);
                            List<Action> actions = new ArrayList<>();
                            actions.add(ActionFactory.getBindIPv6Action(binding));
                            if (binding.getType() == 1) {
                                if (!globalIPNum.containsKey(binding.getSwitchPort())) {
                                    globalIPNum.put(binding.getSwitchPort(), 0);
                                }
                                globalIPNum.put(binding.getSwitchPort(), globalIPNum.get(binding.getSwitchPort())+1);
                            }
                            saviProvider.pushActions(actions);
                        }
                    }

                }
                dadTimer.reschedule(TIMER_DELAY, TimeUnit.SECONDS);
            }
        });
        dadTimer.reschedule(100, TimeUnit.MILLISECONDS);


        //周期发送探测包
        ScheduledExecutorService detectionSes = threadPoolService.getScheduledExecutor();
        detectionTimer=new SingletonTask(detectionSes, new Runnable() {
            @Override
            public void run() {
                sendDetectionMessage();
                detectionTimer.reschedule(60, TimeUnit.SECONDS);
            }
        });
        detectionTimer.reschedule(40, TimeUnit.SECONDS);
    }

    //目标不可达检测
    private void sendDetectionMessage(Binding<IPv6Address> binding){
        Ethernet ethernet=new Ethernet();

        IPv6 iPv6 = new IPv6();

        ICMPv6 icmPv6=new ICMPv6();

        //options   source link layer address
        List<ICMPv6Option> options=new ArrayList<>();
        ICMPv6Option icmPv6Option=new ICMPv6Option((byte) 1, (byte)1);
        byte[] macByte=CONTROLLER_MAC.getBytes();
        byte[] data=icmPv6Option.getData();
        data[0]=icmPv6Option.getCode();
        data[1]=icmPv6Option.getLength();
        for(int i=2;i<data.length;i++){
            data[i]=macByte[i-2];
        }
        options.add(icmPv6Option);
        //icmpv6
        icmPv6.setParent(iPv6);
        icmPv6.setICMPv6Type(ICMPv6.NEIGHBOR_SOLICITATION);     //type
        icmPv6.setICMPv6Code((byte) 0);     //code
        icmPv6.setChecksum((short)0);
        icmPv6.setTargetAddress(binding.getAddress());      //targetAddress
        icmPv6.setOptions(options);     //icmpv6 options
//        short checkSum=calculateCheckSum(icmPv6);
//        icmPv6.setChecksum(checkSum);       //checkSum计算不对 0x5eb0 h1 递减2
        short ckSum=0x5eb0;
        long dst=binding.getMacAddress().getLong();
        ckSum-=(dst-1)*2;
        icmPv6.setChecksum(ckSum);

        //ipv6
        iPv6.setParent(ethernet);
        //traffic class
        iPv6.setTrafficClass((byte)0);
        //flow label
        iPv6.setFlowLabel(0);
        //payload length 序列化时自动装填
        //iPv6.setPayloadLength((byte)/*(icmPv6.serialize().length)*/32);
        iPv6.setNextHeader(IpProtocol.IPv6_ICMP);
        iPv6.setHopLimit((byte)255);
        iPv6.setSourceAddress(CONTROLLER_IP);
        iPv6.setDestinationAddress(binding.getAddress());
        iPv6.setPayload(icmPv6);

        ethernet.setPayload(iPv6);
        ethernet.setDestinationMACAddress(binding.getMacAddress());
        ethernet.setSourceMACAddress(CONTROLLER_MAC);
        ethernet.setEtherType(EthType.IPv6);

        List<Action> actions=new ArrayList<>();
        actions.add(ActionFactory.getPacketOutAction(ethernet, binding.getSwitchPort(), OFPort.CONTROLLER));
        saviProvider.pushActions(actions);
        long time=System.currentTimeMillis();
        synchronized (detectionContainer){
            detectionContainer.put(binding.getSwitchPort(), time);
        }
    }
    private void sendDetectionMessage(){
        for(Binding<?> binding : pool.getAllBindings()){
            IPAddress ipAddress=binding.getAddress();
            if(binding.getType()==0){
                if(ipAddress.getIpVersion()==IPVersion.IPv6){
                    Binding<IPv6Address> bind=(Binding<IPv6Address>)binding;
                    sendDetectionMessage(bind);
                }
            }

        }
    }

    private short calculateCheckSum(ICMPv6 icmPv6){
        int checkSum=0;
        byte[] data=icmPv6.serialize();
        for(int i=0;i<data.length;i+=2){
            if (i == data.length - 1) {
                checkSum+=data[i];
            }else {
                checkSum+=data[i]+data[i+1]<<8;
            }
            checkSum=(checkSum&0xffff)+checkSum>>16;
        }

        return (short) ((~checkSum)&0xffff);
    }

    private void sendNAMessage(Binding<IPv6Address> srcBind, Binding<IPv6Address> dstBind){
        ICMPv6 icmPv6=new ICMPv6();
        icmPv6.setICMPv6Type((byte)136);
        icmPv6.setICMPv6Code((byte)0);
//        icmPv6.setChecksum((short) 0xf5d0);
        icmPv6.setRouterFlag(true);
        icmPv6.setSolicitedFlag(true);
        icmPv6.setOverrideFlag(false);
        icmPv6.setTargetAddress(dstBind.getAddress());

        short chk=(short) 0xf5d0;
        chk-=2*(dstBind.getMacAddress().getLong()-1);
        icmPv6.setChecksum(chk);

        IPv6 iPv6=new IPv6();
        icmPv6.setParent(iPv6);
        iPv6.setPayload(icmPv6);
        iPv6.setTrafficClass((byte)0);
        iPv6.setFlowLabel(0);
        iPv6.setPayloadLength((short)24);
        iPv6.setNextHeader(IpProtocol.IPv6_ICMP);
        iPv6.setHopLimit((byte)255);
        iPv6.setSourceAddress(srcBind.getAddress());
        iPv6.setDestinationAddress(dstBind.getAddress());

        Ethernet ethernet=new Ethernet();
        iPv6.setParent(ethernet);
        ethernet.setPayload(iPv6);
        ethernet.setSourceMACAddress(srcBind.getMacAddress());
        ethernet.setDestinationMACAddress(dstBind.getMacAddress());
        ethernet.setEtherType(EthType.IPv6);

        List<Action> actions=new ArrayList<>();
        actions.add(Action.ActionFactory.getPacketOutAction(ethernet, dstBind.getSwitchPort(), OFPort.CONTROLLER));
        saviProvider.pushActions(actions);
    }

}

//    //发送ping6
//    private void sendDetectionMessage(){
//        List<Action> actions=new ArrayList<>();
//
//        for(Binding<?> binding : pool.getAllBindings()) {
//            if(binding.getStatus()!=BindingStatus.BOUND) {
//                continue;
//            }
//            IPAddress<?> ipAddr=binding.getAddress();
//            if(ipAddr instanceof IPv4Address)
//                continue;
//            IPv6Address sourceAddress=(IPv6Address)ipAddr;
//
//            Ethernet ethernet=new Ethernet();
//
//            IPv6 iPv6 = new IPv6();
//
//            ICMPv6 icmPv6=new ICMPv6();
//
//            //data
////            byte[] msg="hello this is controller".getBytes();
//            //icmpv6
//            icmPv6.setParent(iPv6);
//            icmPv6.setICMPv6Type(ICMPv6.ECHO_REQUEST);     //type
//            icmPv6.setICMPv6Code((byte) 0);     //code
//            short checkSum=calculateCheckSum(icmPv6);
//            icmPv6.setChecksum(checkSum);       //checkSum
//
//            //ipv6
//            iPv6.setParent(ethernet);
//            //traffic class
//            iPv6.setTrafficClass((byte)0);
//            //flow label
//            iPv6.setFlowLabel(0);
//            //payload length 序列化时自动装填
//            //iPv6.setPayloadLength((byte)/*(icmPv6.serialize().length)*/32);
//            iPv6.setNextHeader(IpProtocol.IPv6_ICMP);
//            iPv6.setHopLimit((byte)64);
//            iPv6.setSourceAddress(CONTROLLER_IP);
//            iPv6.setDestinationAddress(sourceAddress);
//            iPv6.setPayload(icmPv6);
//
//            ethernet.setPayload(iPv6);
//            ethernet.setDestinationMACAddress(binding.getMacAddress());
//            ethernet.setSourceMACAddress(CONTROLLER_MAC);
//            ethernet.setEtherType(EthType.IPv6);
//
//            actions.add(ActionFactory.getPacketOutAction(ethernet, binding.getSwitchPort(), OFPort.CONTROLLER));
//            detectionContainer.put(binding.getSwitchPort(), System.currentTimeMillis());
//        }
////        for(AuthTable authTable : authTableMap.values()){
////
////
////        }
//        saviProvider.pushActions(actions);
//    }
