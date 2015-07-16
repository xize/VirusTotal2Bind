package me.xephore.virustotal2bind.packets;

import me.xephore.virustotal2bind.enums.PacketType;

public interface Packet {
	
	/**
	 * returns the name of the packet
	 * 
	 * @author xize
	 * @return String
	 */
	public String getName();
	
	/**
	 * returns the packet type
	 * 
	 * @author xize
	 * @return PacketType
	 */
	public PacketType getType();
	
	/**
	 * returns the parameters!
	 * 
	 * @author xize
	 * @return E
	 */
	public String[] getParams();
	
	/**
	 * returns true if the packet is safe to sent
	 * 
	 * @author xize
	 * @return boolean
	 */
	public boolean isPacketComplete();

}
