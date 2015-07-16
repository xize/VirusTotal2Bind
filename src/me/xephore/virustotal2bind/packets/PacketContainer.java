package me.xephore.virustotal2bind.packets;

import me.xephore.virustotal2bind.GuiApi;
import me.xephore.virustotal2bind.enums.AppType;

public abstract class PacketContainer {

	private GuiApi gui;
	private final Packet packet;

	public PacketContainer(GuiApi gui, Packet packet) {
		this.gui = gui;
		this.packet = packet;
	}
	
	public PacketContainer(Packet packet) {
		this.packet = packet;
	}

	/**
	 * returns the gui
	 * 
	 * @author xize
	 * @return GuiApi
	 */
	public GuiApi getGui() {
		return gui;
	}

	/**
	 * returns the fetched object
	 * 
	 * @author xize
	 * @param call - returns the callable
	 * @return String[]
	 */
	public abstract String[] execute();
	
	/**
	 * returns the packet
	 * 
	 * @author xize
	 * @return Packet
	 */
	public Packet getPacket() {
		return packet;
	}

	/**
	 * returns the app type enum
	 * 
	 * @author xize
	 * @return AppType 
	 */
	public abstract AppType getType();

}
