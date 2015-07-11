package me.xephore.virustotal2bind.events;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import me.xephore.virustotal2bind.GuiApi;
import me.xephore.virustotal2bind.packets.DomainPacket;
import me.xephore.virustotal2bind.packets.IPAddressPacket;
import me.xephore.virustotal2bind.packets.Packet;
import me.xephore.virustotal2bind.packets.PacketFactory;

public class ButtonEvent implements ActionListener {
	
	private final GuiApi gui;
	
	public ButtonEvent(GuiApi gui) {
		this.gui = gui;
	}

	@Override
	public void actionPerformed(ActionEvent e) {
		if(e.getSource().equals(gui.getButton())) {
			gui.getTextArea().setText("");
			gui.getStatus().setText("status: verifying url...");
			gui.getDetections().setText("detections: 0");
			String url = gui.getTextField().getText();
			if(DomainPacket.isUrl(url) || IPAddressPacket.isIp(url)) {
				gui.getStatus().setText("status: url verified, fetching from virustotal!");
				Packet packet1 = null;
				if(DomainPacket.isUrl(url)) {
					DomainPacket packet = new DomainPacket();
					packet1 = packet;
					packet.setDomainNameParam(url);
				
					System.out.println("type: this url is a domain.");
				
				} else if(IPAddressPacket.isIp(url)) {	
					IPAddressPacket packet = new IPAddressPacket();
					packet1 = packet;
					packet.setIpAdressParam(url);
				
					System.out.println("type: this url is a ip");
				} else {
					gui.getStatus().setText("status: unknown protocol!");
				}
				String bind = PacketFactory.getFactory().sentPacket(packet1);
				gui.getStatus().setText("status: fetching complete!");
				gui.getTextArea().setText(bind);
				//gui.getDetections().setText("detections: " + stat.getDetections());
				//gui.getTextArea().setText(stat.getBindFormat());
			} else {
				gui.getStatus().setText("status: url invalid!");
			}
		}
	}

}
