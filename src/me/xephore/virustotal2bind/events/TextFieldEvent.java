package me.xephore.virustotal2bind.events;

import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;

import me.xephore.virustotal2bind.GuiApi;
import me.xephore.virustotal2bind.packets.DomainPacket;
import me.xephore.virustotal2bind.packets.IPAddressPacket;
import me.xephore.virustotal2bind.packets.Packet;
import me.xephore.virustotal2bind.packets.PacketFactory;

public class TextFieldEvent implements KeyListener {

	private final GuiApi gui;
	
	public TextFieldEvent(GuiApi gui) {
		this.gui = gui;
	}
	
	@Override
	public void keyTyped(KeyEvent e) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void keyPressed(KeyEvent e) {
		if(e.getKeyCode() == KeyEvent.VK_ENTER) {
			if(e.getSource().equals(gui.getTextField())) {
				reset();
				
				String url = gui.getTextField().getText();
				
				gui.getStatus().setText("status: verifying text field....");
				if(DomainPacket.isUrl(url) || IPAddressPacket.isIp(url)) {
					
					gui.getStatus().setText("status: url verified, fetching from virustotal!");
					Packet packet1 = null;
					
					if(DomainPacket.isUrl(url)) {
						DomainPacket packet = new DomainPacket();
						packet1 = packet;
						packet.setDomainNameParam(url);
					} else if(IPAddressPacket.isIp(url)) {	
						IPAddressPacket packet = new IPAddressPacket();
						packet1 = packet;
						packet.setIpAdressParam(url);
					} else {
						gui.getStatus().setText("status: unknown protocol!");
						return;
					}
					
					gui.getStatus().setText("status: fetching data...");
					String[] bind = PacketFactory.getFactory().sentPacket(packet1);
					gui.getStatus().setText("status: disconnected, idle...");
					gui.getTextArea().setText(bind[0]);
					gui.getDetections().setText(bind[1]);
				
				} else {
					gui.getStatus().setText("status: url invalid!");
				}
			}
		}
	}
	
	public void reset() {
		gui.getTextArea().setText("");
		gui.getStatus().setText("idle...");
		gui.getDetections().setText("detections: 0");
	}

	@Override
	public void keyReleased(KeyEvent e) {
		// TODO Auto-generated method stub
		
	}



}
