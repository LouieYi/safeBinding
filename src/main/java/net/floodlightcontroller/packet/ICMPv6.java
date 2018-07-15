package net.floodlightcontroller.packet;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.projectfloodlight.openflow.types.IPv6Address;

/**
 * 
 * @author Yu Zhou (yuz.thu@gmail.com)
 */
public class ICMPv6 extends BasePacket {

	protected byte icmpv6Type;
	protected byte icmpv6Code;
	protected short checksum;
	protected boolean routerFlag;
	protected boolean solicitedFlag;
	protected boolean overrideFlag;
	protected List<ICMPv6Option> options = null;
	protected IPv6Address targetAddress;
	protected byte[] cache;
	
	protected static final Map<Byte, Integer> paddingMap;
	
	private static final byte ROUTER_FLAG_MASK   = (byte)0x80;
	private static final byte SOLIITED_FLAG_MASK = (byte)0x40;
	private static final byte OVERRIDE_FLAG_MASK = (byte)0x20;
	
	public static final byte DESTINATION_UNREACHABLE = 1;
	public static final byte PACKET_TOO_BIG = 2;
	public static final byte TIME_EXCEEDED = 3;
	public static final byte PARAMETER_PROBLEM = 4;
	public static final byte ECHO_REQUEST = (byte)128;
	public static final byte ECHO_REPLY = (byte)129;
	public static final byte ROUTER_SOLICITATION = (byte)133;
	public static final byte ROUTER_ADVERTSEMENT = (byte)134;
	public static final byte NEIGHBOR_SOLICITATION = (byte)135;
	public static final byte NEIGHBOR_ADVERTISEMENT = (byte)136;
	
	static{
		paddingMap = new HashMap<Byte,Integer>();
		paddingMap.put(DESTINATION_UNREACHABLE, 0x4);
		paddingMap.put(PACKET_TOO_BIG, 0x4);
		paddingMap.put(TIME_EXCEEDED, 0x4);
		paddingMap.put(PARAMETER_PROBLEM, 0x4);
		paddingMap.put(ECHO_REQUEST, 0x4);
		paddingMap.put(ECHO_REPLY, 0x4);
		paddingMap.put(ROUTER_ADVERTSEMENT, 0x4);
		paddingMap.put(ROUTER_SOLICITATION, 0x4);
		paddingMap.put(NEIGHBOR_ADVERTISEMENT, 0x4);
		paddingMap.put(NEIGHBOR_SOLICITATION, 0x4);
		
	}
	
	public IPv6Address getTargetAddress() {
		return targetAddress;
	}

	public void setTargetAddress(IPv6Address targetAddress) {
		this.targetAddress = targetAddress;
	}

	public byte getICMPv6Type() {
		return icmpv6Type;
	}

	public void setICMPv6Type(byte icmpv6Type) {
		this.icmpv6Type = icmpv6Type;
	}

	public byte getICMPv6Code() {
		return icmpv6Code;
	}

	public void setICMPv6Code(byte icmpv6Code) {
		this.icmpv6Code = icmpv6Code;
	}

	public short getChecksum() {
		return checksum;
	}

	public void setChecksum(short checksum) {
		this.checksum = checksum;
	}

	@Override
	public int hashCode() {
        final int prime = 5807;
        int result = super.hashCode();
        result = prime * result + icmpv6Type;
        result = prime * result + icmpv6Code;
        result = prime * result + checksum;
        return result;
	}
	@Override
	public byte[] serialize() {
		// TODO Auto-generated method stub
		
		int length = 4;
		int padding = 0;
		if(paddingMap.containsKey(this.icmpv6Type)){
			padding = paddingMap.get(this.icmpv6Type);
			length += padding;
		}
		if(icmpv6Type == NEIGHBOR_SOLICITATION){
			length += 16;
		}
		for(ICMPv6Option option:options){
			length += (int)option.getLength()*8 + 2;
		}
		
		byte[] data = new byte[length];
		ByteBuffer bb = ByteBuffer.wrap(data);
		bb.put(this.icmpv6Type);
		bb.put(this.icmpv6Code);
		bb.putShort(this.checksum);
		for(int i =0;i<padding;i++){
			bb.put((byte)0);
		}
		if(icmpv6Type == NEIGHBOR_SOLICITATION){
			bb.put(targetAddress.getBytes());
		}
		for(ICMPv6Option option:options){
			bb.put(option.serilize());
		}
		
		return cache;
	}

	@Override
	public IPacket deserialize(byte[] data, int offset, int length) throws PacketParsingException {
		// TODO Auto-generated method stub
		cache = new byte[length];	
		for(int i=0;i<length;i++){
			cache[i] = data[offset+i];
		}
		
		ByteBuffer bb = ByteBuffer.wrap(data, offset, length);
		this.routerFlag = false;
		this.overrideFlag = false;
		this.solicitedFlag = false;
		this.icmpv6Type = bb.get();
		this.icmpv6Code = bb.get();
		this.checksum = bb.getShort();
		
		if(icmpv6Type == NEIGHBOR_ADVERTISEMENT){
			byte tmp = bb.get();
			
			this.routerFlag = ((tmp&ROUTER_FLAG_MASK)==ROUTER_ADVERTSEMENT);
			this.solicitedFlag = ((tmp&SOLIITED_FLAG_MASK)==SOLIITED_FLAG_MASK);
			this.overrideFlag = ((tmp&OVERRIDE_FLAG_MASK)==OVERRIDE_FLAG_MASK);
			
			bb.get();
			bb.getShort();
		}
		else if(paddingMap.containsKey(this.icmpv6Type)){
			bb.position(bb.position()+paddingMap.get(this.icmpv6Type));
		}
		
		if(icmpv6Type == NEIGHBOR_SOLICITATION||icmpv6Type == NEIGHBOR_ADVERTISEMENT){
			options = new ArrayList<>();
			byte[] tmp  = new byte[16];
			bb.get(tmp, 0, 16);
			targetAddress = IPv6Address.of(tmp);
		}
		else{
			targetAddress = null;
			options = ICMPv6Option.getOptions(data, bb.position());
		}
		
		return this;
	}
}
