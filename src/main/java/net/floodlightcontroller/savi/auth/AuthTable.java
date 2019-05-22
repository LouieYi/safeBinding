package net.floodlightcontroller.savi.auth;

import net.floodlightcontroller.devicemanager.SwitchPort;
import net.floodlightcontroller.savi.binding.BindingStatus;
import org.projectfloodlight.openflow.types.IPv6Address;
import org.projectfloodlight.openflow.types.MacAddress;

/**
 * 验证SLAAC和DHCPv6消息的验证表
 */
public class AuthTable {

    private IPv6Address linkLocalAddresss;
    private IPv6Address globalUnicastAddress;
    private IPv6Address newIPAddress;
    private MacAddress macAddress;
    private SwitchPort switchPort;
    private long globalGenerateTime;
    private long localGenerateTime;
    private long preferedLifetime;
    private long validTime;
    private BindingStatus status;

    private static final int PRIME = 43;

    @Override
    public int hashCode() {
        int result = 1;

        result = PRIME*result + ((linkLocalAddresss == null)?0:linkLocalAddresss.hashCode());
        result = PRIME*result + ((globalUnicastAddress == null)?0:globalUnicastAddress.hashCode());
        result = PRIME*result + ((newIPAddress == null)?0:globalUnicastAddress.hashCode());
        result = PRIME*result + ((macAddress == null)?0:macAddress.hashCode());
        result = PRIME*result + ((switchPort == null)?0:switchPort.hashCode());

        return result;
    }

    public AuthTable(){}
    public AuthTable(IPv6Address linkLocalAddresss, MacAddress macAddress, SwitchPort switchPort){
        this.linkLocalAddresss=linkLocalAddresss;
        this.macAddress=macAddress;
        this.switchPort=switchPort;
    }

    public IPv6Address getLinkLocalAddresss() {
        return linkLocalAddresss;
    }

    public void setLinkLocalAddresss(IPv6Address linkLocalAddresss) {
        if(linkLocalAddresss==null)
            this.localGenerateTime=0;
        this.linkLocalAddresss = linkLocalAddresss;
    }

    public IPv6Address getGlobalUnicastAddress() {
        return globalUnicastAddress;
    }

    public void setGlobalUnicastAddress(IPv6Address globalUnicastAddress) {
        if(globalUnicastAddress==null)
            this.globalGenerateTime=0;
        this.globalUnicastAddress = globalUnicastAddress;
    }

    public MacAddress getMacAddress() {
        return macAddress;
    }

    public void setMacAddress(MacAddress macAddress) {
        this.macAddress = macAddress;
    }

    public SwitchPort getSwitchPort() {
        return switchPort;
    }

    public void setSwitchPort(SwitchPort switchPort) {
        this.switchPort = switchPort;
    }

    public long getGlobalGenerateTime() {
        return globalGenerateTime;
    }

    public void setGlobalGenerateTime() {
        this.globalGenerateTime = System.currentTimeMillis();
    }

    public long getLocalGenerateTime() {
        return localGenerateTime;
    }

    public void setLocalGenerateTime() {
        this.localGenerateTime = System.currentTimeMillis();
    }

    public long getValidTime() {
        return validTime;
    }

    public void setValidTime(long validTime) {
        this.validTime = validTime;
    }

    public BindingStatus getStatus() {
        return status;
    }

    public void setStatus(BindingStatus status) {
        this.status = status;
    }

    public IPv6Address getNewIPAddress() {
        return newIPAddress;
    }

    public void setNewIPAddress(IPv6Address newIPAddress) {
        this.newIPAddress = newIPAddress;
    }

    public long getPreferedLifetime() {
        return preferedLifetime;
    }

    public void setPreferedLifetime(long preferedLifetime) {
        this.preferedLifetime = preferedLifetime;
    }
}
