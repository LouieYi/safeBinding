package net.floodlightcontroller.savi.auth;

import com.sun.xml.internal.ws.util.QNameMap;
import io.netty.util.internal.ConcurrentSet;
import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.SwitchPort;
import net.floodlightcontroller.packet.*;
import net.floodlightcontroller.savi.binding.BindingManager;
import net.floodlightcontroller.savi.binding.BindingStatus;
import net.floodlightcontroller.topology.ITopologyService;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.OFVersion;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.*;

import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class Authentication implements IFloodlightModule, IOFMessageListener {

    //验证表
    private Map<SwitchPort, AuthTable> authTableMap;
    //刚申请的地址，且在绑定表中存在
    private Map<SwitchPort, Long> tempararyApply;
    //address set
    private Set<IPv6Address> ipv6AddressSet;
    //交换机端口阈值
    private Map<SwitchPort, Integer> thresholds;
    //交换机端口异常次数
    private Map<SwitchPort, Integer> counts;
    //
    private Map<Integer, SwitchPort> transactionPort;

    //
    private Map<SwitchPort, ICMPv6Option> prefixInfo;   //slaac集合 not init
    private Map<SwitchPort, DHCPv6Option> dhcpInfo;   //dhcpv6集合 not init

    //DHCPv6服务器端口
    List<SwitchPort> dhcpPorts;

    private IFloodlightProviderService floodlightProvider;
    private ITopologyService topologyService;
    private IOFSwitchService switchService;

    //前两个字节掩码
    private static final IPv6Address MASK_HEAD=IPv6Address.of("ffff::");
    //DAD检测时间
    private static final long interval=5000;

    private BindingManager manager;

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
        List<Class<? extends IFloodlightService>> dependencies=new ArrayList<>();
        dependencies.add(IFloodlightService.class);
        dependencies.add(ITopologyService.class);
        dependencies.add(IOFSwitchService.class);
        return dependencies;
    }

    @Override
    public void init(FloodlightModuleContext context) throws FloodlightModuleException {
        floodlightProvider=context.getServiceImpl(IFloodlightProviderService.class);
        topologyService=context.getServiceImpl(ITopologyService.class);
        switchService=context.getServiceImpl(IOFSwitchService.class);

        authTableMap=new ConcurrentHashMap<>();
        tempararyApply=new ConcurrentHashMap<>();
        ipv6AddressSet=new ConcurrentSet<>();
        thresholds=new ConcurrentHashMap<>();
        counts=new ConcurrentHashMap<>();
        transactionPort=new ConcurrentHashMap<>();
        dhcpPorts=new ArrayList<>();
    }

    @Override
    public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {

    }

    @Override
    public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {

        if(msg.getType() == OFType.PACKET_IN)
            return processPacketIn(sw, (OFPacketIn) msg, cntx);
        System.out.println("******ERROR*******");
        return Command.CONTINUE;
    }

    private Command processPacketIn(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx){
        OFPort inPort = (pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi.getInPort()
                : pi.getMatch().get(MatchField.IN_PORT));

        Ethernet eth= IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);

        MacAddress macAddress=eth.getSourceMACAddress();
        SwitchPort switchPort=new SwitchPort(sw.getId(), inPort);


        if(isDHCPv6(eth)){

            //非边缘交换机端口收到 即边缘交换机转发过来的--->不做处理---->转发
            if (!topologyService.isEdge(switchPort.getSwitchDPID(), switchPort.getPort())) {
                return Command.CONTINUE;
            }

            return processDHCPv6(switchPort, macAddress, eth);

        }else if(isSLAAC(eth)) {
            IPv6 ipv6 = (IPv6)eth.getPayload();

            ICMPv6 icmPv6= (ICMPv6) ipv6.getPayload();
            //非边缘交换机端口收到 即边缘交换机转发过来的--->不做处理---->转发
            if (icmPv6.getICMPv6Type() !=ICMPv6.ROUTER_ADVERTSEMENT
                    &&!topologyService.isEdge(switchPort.getSwitchDPID(), switchPort.getPort())) {
                return Command.CONTINUE;
            }
            return processSLAAC(switchPort, macAddress, ipv6);

        }

        return Command.CONTINUE;
    }

    private Command processSLAAC(SwitchPort switchPort, MacAddress macAddress, IPv6 ipv6){
        ICMPv6 icmPv6= (ICMPv6) ipv6.getPayload();
        IPv6Address sourceAddress=ipv6.getSourceAddress();

        switch(icmPv6.getICMPv6Type()){
            case ICMPv6.ROUTER_SOLICITATION:
                return Command.CONTINUE;  //  RS消息不需要验证
            case ICMPv6.ROUTER_ADVERTSEMENT:
                return processRouterAdvertsement(switchPort, icmPv6, macAddress);
            case ICMPv6.NEIGHBOR_SOLICITATION:
                return processNeighborSolicit(switchPort, icmPv6, sourceAddress, macAddress);
            case ICMPv6.NEIGHBOR_ADVERTISEMENT:
                return processNeighborAdvertisement(switchPort, icmPv6, sourceAddress, macAddress);
        }
        return Command.CONTINUE;
    }

    private Command processRouterAdvertsement(SwitchPort switchPort, ICMPv6 icmPv6, MacAddress macAddress){
        //边缘交换机端口收到的RA消息为伪造消息
        if (topologyService.isEdge(switchPort.getSwitchDPID(), switchPort.getPort())) {
            handleException(switchPort);
            return Command.STOP;
        }

        //slaac配置
        if (!icmPv6.isManagedAddressConfiguration()&&!icmPv6.isOtherConfiguration()) {
            //绑定前缀信息到switchPort上
            for(ICMPv6Option icmPv6Option : icmPv6.getOptions()){
                if (icmPv6Option.getCode() == 3) {
                    DatapathId dpid=switchPort.getSwitchDPID();
                    IOFSwitch sw=switchService.getSwitch(dpid);
                    for(OFPort port : sw.getEnabledPortNumbers()){
                        if(port.equals(switchPort.getPort())){
                            continue;
                        }
                        //边缘交换机端口 绑定前缀信息
                        if (topologyService.isEdge(dpid, port)) {
                            prefixInfo.put(new SwitchPort(dpid, port), icmPv6Option);
                        }else {
                            //
                        }
                    }
                }
            }
        }
        //dhcpv6配置 RA暂不处理
        else if (icmPv6.isManagedAddressConfiguration()) {
            dhcpInfo.put(switchPort, null);
        }

        return Command.CONTINUE;
    }
    /*
    private void bfs(){

    }
*/
    private Command processNeighborSolicit(SwitchPort switchPort, ICMPv6 icmPv6, IPv6Address sourceAddress, MacAddress macAddress){

        if (sourceAddress.equals(IPv6Address.FULL_MASK)) {      //源地址为::
            IPv6Address targetAddress=icmPv6.getTargetAddress();
            //本地链路DAD
            if (targetAddress.applyMask(MASK_HEAD).equals(IPv6Address.of("fe80::"))) {
                //本地链路地址已经存在，判断是否超出阈值--->异常
                if (authTableMap.containsKey(switchPort)) {
                    if (thresholds.get(switchPort) <= counts.get(switchPort)) {
                        handleException(switchPort);
                        return Command.STOP;
                    }
                    //没有超出阈值 计数加1
                    counts.put(switchPort, counts.get(switchPort)+1);
                }
                long now=System.currentTimeMillis();

                /*
                //地址是否已经存在  -->暂时不考虑同时NS的情况，只考虑NA
                SwitchPort sp=linkLocalAddressMap.get(targetAddress);
                //地址已存在
                if (sp != null) {
                    AuthTable existTable=authTableMap.get(sp);
                    //先前的绑定表建立不成功，删除  todo 留待观察
                    if(now<existTable.getLocalGenerateTime()+interval){
                        authTableMap.remove(sp);
                        linkLocalAddressMap.remove(targetAddress);
                    }
                    //可能有一些问题？？ 先前的主机离开网络了--->暂时不考虑
                    return Command.CONTINUE;
                }
                */
                //地址已被占用
                for(AuthTable a : authTableMap.values()){
                    if(a.getLinkLocalAddresss().equals(targetAddress))
                        return Command.CONTINUE;
                }
                //正常，建立验证表
                AuthTable authTable=new AuthTable();
                authTable.setLinkLocalAddresss(targetAddress);
                authTable.setMacAddress(macAddress);
                authTable.setSwitchPort(switchPort);
                authTable.setLocalGenerateTime();
                authTable.setStatus(BindingStatus.INIT);

                authTableMap.put(switchPort, authTable);
                //之后再做考虑
                /*if (ipv6AddressSet.contains(targetAddress)) {
                    tempararyApply.put(switchPort, now);
                }else {
                    ipv6AddressSet.add(targetAddress);
                }*/

                return Command.CONTINUE;
            }else {     //绑定表已经有fe80的地址了 全局链路DAD
                /*
                if (check(switchPort, macAddress, targetAddress, false)) {
                    return Command.CONTINUE;    //  这里好像没什么用
                }
                */
                AuthTable authTable=authTableMap.get(switchPort);
                //没有绑定该端口时 或者 已绑定该端口的globalUnicastAddress时 是非法NS消息
                if(authTable==null||authTable.getGlobalUnicastAddress()!=null) {
                    handleException(switchPort);
                    return Command.STOP;
                }

                long now=System.currentTimeMillis();
/*
                    //验证全局单播地址是否已使用 暂时不考虑同时NS
                    SwitchPort sp=globalUnicastAddressMap.get(targetAddress);

                    //地址已存在
                    if (sp != null) {
                        AuthTable existTable=authTableMap.get(sp);
                        //先前的绑定表建立不成功，删除
                        if(now<existTable.getGlobalGenerateTime()+interval){
                            authTableMap.remove(sp);
                        }
                        //可能有一些问题？？ 先前的主机离开网络了
                        return Command.CONTINUE;
                    }
*/

                //端口不是slaac配置端口
                if (!prefixInfo.containsKey(switchPort)) {
                    handleException(switchPort);
                    return Command.STOP;
                }
                //地址已被占用
                for(AuthTable a : authTableMap.values()){
                   if(a.getGlobalUnicastAddress().equals(targetAddress))
                       return Command.CONTINUE;
                }
                //前缀匹配
                ICMPv6Option icmPv6Option=prefixInfo.get(switchPort);
                byte prefixLen=icmPv6Option.getPrefixLength();
                IPv6Address prefix=icmPv6Option.getPrefixAddress();
                //生成前缀掩码
                byte[] mask=new byte[16];
                int m=prefixLen/8;
                int n=prefixLen%8;
                for(int i=0;i<m;i++){
                    mask[i]=(byte)0xff;
                }
                mask[m]=(byte)(0xff>>(8-n));

                IPv6Address iPv6AddressMask=IPv6Address.of(mask);
                //前缀不匹配
                if(!targetAddress.applyMask(iPv6AddressMask).equals(prefix.applyMask(iPv6AddressMask))){
                    handleException(switchPort);
                    return Command.STOP;
                }

                authTable.setGlobalUnicastAddress(targetAddress);
                authTable.setGlobalGenerateTime();
                authTable.setStatus(BindingStatus.BOUND);
                authTable.setValidTime(prefixInfo.get(switchPort).getValidLifetime());      //由RA消息得到

                authTableMap.put(switchPort, authTable);
                //暂不考虑
                /*
                if (ipv6AddressSet.contains(targetAddress)) {
                    tempararyApply.put(switchPort, now);
                }else {
                    ipv6AddressSet.add(targetAddress);
                }
*/
                return Command.CONTINUE;
            }
        }else{      //不是DAD检测
            if(check(switchPort, macAddress, sourceAddress, false)
                    ||check(switchPort, macAddress, sourceAddress, true)){
                return Command.CONTINUE;
            }else{
                handleException(switchPort);
                return Command.STOP;
            }
        }
    }

    private Command processNeighborAdvertisement(SwitchPort switchPort, ICMPv6 icmPv6, IPv6Address sourceAddress, MacAddress macAddress){
        IPv6Address targetAddress=icmPv6.getTargetAddress();
        //源地址不匹配单播地址也不匹配链路地址或者和目标地址不一致
        if((!check(switchPort, macAddress, sourceAddress, false)
                &&!check(switchPort, macAddress, sourceAddress, true)
        )||targetAddress!=sourceAddress){

            handleException(switchPort);
            return Command.STOP;
        }
        //不分响应DAD还是其他
        /*
        if (icmPv6.isSolicitedFlag()) {     //响应DAD消息
            Iterator<Map.Entry<SwitchPort, Long>> iterator=tempararyApply.entrySet().iterator();
            while(iterator.hasNext()){
                Map.Entry<SwitchPort, Long> e=iterator.next();
                if(e.getKey()==switchPort) continue;
                if(e.getValue()+interval<System.currentTimeMillis()) continue;

                AuthTable authTable=authTableMap.get(e.getKey());
                if (sourceAddress.applyMask(MASK_HEAD).equals(IPv6Address.of("fe80::"))) {
                    IPv6Address ipv6Address=authTable.getLinkLocalAddresss();
                    if (sourceAddress.equals(ipv6Address)) {
                        authTable.setLinkLocalAddresss(null);
                        iterator.remove();
                    }
                }else {
                    IPv6Address ipv6Address=authTable.getGlobalUnicastAddress();
                    if (sourceAddress.equals(ipv6Address)) {
                        authTable.setGlobalUnicastAddress(null);
                        iterator.remove();
                    }
                }
            }
        }else {     //solicited Flag为0
            if (sourceAddress.applyMask(MASK_HEAD).equals(IPv6Address.of("fe80::"))) {
                if (!check(switchPort, macAddress, sourceAddress, true)) {
                    handleException(switchPort);
                    return Command.STOP;
                }
                return Command.CONTINUE;
            }else {
                if (!check(switchPort, macAddress, sourceAddress, false)) {
                    handleException(switchPort);
                    return Command.STOP;
                }
                return Command.CONTINUE;
            }
        }*/
        return Command.CONTINUE;
    }

    private Command processDHCPv6(SwitchPort switchPort, MacAddress macAddress, Ethernet eth){
        IPv6 iPv6= (IPv6) eth.getPayload();
        UDP udp = (UDP)iPv6.getPayload();
        DHCPv6 dhcp = (DHCPv6)udp.getPayload();
        if (dhcpPorts.contains(switchPort)) {
            switch(dhcp.getMessageType()){
                case ADVERTISE:
                    return processAdervtise(switchPort);
                case REPLY:
                    return processReply(switchPort, eth);
                case RECONFIGURE:
                    return Command.CONTINUE;
                default:
                    return Command.STOP;
            }
        }else {
            switch(dhcp.getMessageType()){
                case SOLICIT:
                    return processSolicit(switchPort, macAddress, iPv6);
                case REQUEST:
                    return processRequest(switchPort, macAddress, iPv6);
                case CONFIRM:
                    return processConfirm(switchPort, macAddress, iPv6);
                case RENEW:
                case REBIND:
                case RELEASE:
                case DECLINE:
                case INFORMATION_REQUEST:
                default:
                    handleException(switchPort);
                    return Command.STOP;
            }
        }
    }

    private Command processSolicit(SwitchPort switchPort, MacAddress macAddress, IPv6 iPv6){
        //检验本地链路地址
        if(clientValid(switchPort, macAddress, iPv6)){
            handleException(switchPort);
            return Command.STOP;
        }
        return Command.CONTINUE;
    }

    //todo handle confirm and reply
    private Command processConfirm(SwitchPort switchPort, MacAddress macAddress, IPv6 iPv6){
        if(authTableMap.containsKey(switchPort)){
            if (!clientValid(switchPort, macAddress, iPv6)) {
                handleException(switchPort);
                return Command.STOP;
            }
        }

        return Command.CONTINUE;
    }

    private Command processAdervtise(SwitchPort switchPort){
        if (!dhcpPorts.contains(switchPort)) {
            handleException(switchPort);
            return Command.STOP;
        }
        return Command.CONTINUE;
    }

    private Command processRequest(SwitchPort switchPort, MacAddress macAddress, IPv6 iPv6){
        UDP udp = (UDP)iPv6.getPayload();
        DHCPv6 dhcp = (DHCPv6)udp.getPayload();
        if(clientValid(switchPort, macAddress, iPv6)){
            handleException(switchPort);
            return Command.STOP;
        }

        int transactionId=dhcp.getTransactionId();
        transactionPort.put(transactionId, switchPort);

        return Command.CONTINUE;
    }

    private Command processReply(SwitchPort switchPort, Ethernet eth){
        if (!dhcpPorts.contains(switchPort)) {
            handleException(switchPort);
            return Command.STOP;
        }
        IPv6 iPv6= (IPv6) eth.getPayload();
        UDP udp=(UDP) iPv6.getPayload();
        DHCPv6 dhcPv6= (DHCPv6) udp.getPayload();
//        MacAddress macAddress=eth.getDestinationMACAddress();
        int transactionId=dhcPv6.getTransactionId();
        SwitchPort desPort=transactionPort.get(transactionId);
        if(desPort==null) return Command.STOP;

        //默认为成功分配 todo
        IPv6Address targetAddress=dhcPv6.getTargetAddress();
        long validLifeTime=dhcPv6.getValidLifetime();
        AuthTable authTable=authTableMap.get(desPort);
        authTable.setGlobalUnicastAddress(targetAddress);
        authTable.setGlobalGenerateTime();
        authTable.setValidTime(validLifeTime);

        return Command.CONTINUE;
    }

    private boolean clientValid(SwitchPort switchPort, MacAddress macAddress, IPv6 iPv6){
        IPv6Address sourceAddress=iPv6.getSourceAddress();
        IPv6Address destinationAddress=iPv6.getDestinationAddress();
        if (!destinationAddress.equals(IPv6Address.of("ff02::1:2")))
            return false;
        if(!check(switchPort, macAddress, sourceAddress, true))
            return false;
        return true;
    }
    private void handleException(SwitchPort switchPort){

    }

    @SuppressWarnings("Duplicates")
    private boolean isDHCPv6(Ethernet eth){
        if(eth.getEtherType() == EthType.IPv6){
            IPv6 ipv6 = (IPv6)eth.getPayload();
            if(ipv6.getNextHeader().equals(IpProtocol.UDP)){
                UDP udp = (UDP)ipv6.getPayload();
                if(udp.getSourcePort().getPort() == 546 || udp.getDestinationPort().getPort() == 546){
                    return true;
                }
            }
        }
        return false;
    }

    private boolean isSLAAC(Ethernet eth){
        if(eth.getEtherType() == EthType.IPv6){
            IPv6 ipv6 = (IPv6)eth.getPayload();
            if(ipv6.getNextHeader().equals(IpProtocol.IPv6_ICMP)){
                ICMPv6 icmpv6 = (ICMPv6)ipv6.getPayload();
                byte type = icmpv6.getICMPv6Type();
                return type== ICMPv6.ROUTER_SOLICITATION||
                        type== ICMPv6.ROUTER_ADVERTSEMENT||
                        type== ICMPv6.NEIGHBOR_SOLICITATION||
                        type== ICMPv6.NEIGHBOR_ADVERTISEMENT;
            }
        }
        return false;
    }

    /**
     * 验证存在且一致
     * @param switchPort
     * @param macAddress
     * @param iPv6Address
     * @param linkLocalAddress
     * @return
     */
    private boolean check(SwitchPort switchPort, MacAddress macAddress,
                          IPv6Address iPv6Address, boolean linkLocalAddress){
        AuthTable authTable=authTableMap.get(switchPort);
        if(authTable==null) return false;
        long curTime=System.currentTimeMillis();
        if(!linkLocalAddress&&authTable.getGlobalGenerateTime()+authTable.getValidTime()>curTime)
            return false;
        if(authTable.getMacAddress().equals(macAddress))
            return linkLocalAddress?authTable.getLinkLocalAddresss().equals(iPv6Address)
                    :authTable.getGlobalUnicastAddress().equals(iPv6Address);
        return false;
    }

    @Override
    public String getName() {
        return this.getClass().getSimpleName();
    }

    @Override
    public boolean isCallbackOrderingPrereq(OFType type, String name) {
        return false;
    }

    @Override
    public boolean isCallbackOrderingPostreq(OFType type, String name) {
        return type.equals(OFType.PACKET_IN)&&"savi".equals(name);
    }

    public void addDHCPv6Port(SwitchPort switchPort){
        dhcpPorts.add(switchPort);
    }


    class ClientInfo{
        int iaid;
        long duid;

        @Override
        public boolean equals(Object obj) {
            if (!(obj instanceof ClientInfo)) {
                return false;
            }
            ClientInfo clientInfo= (ClientInfo) obj;

            return clientInfo.iaid==this.iaid&&clientInfo.duid==this.duid;
        }

        @Override
        public int hashCode() {
            return iaid;
        }
    }

}
