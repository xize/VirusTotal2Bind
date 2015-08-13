package me.xephore.virustotal2bind.events;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import me.xephore.virustotal2bind.GuiApi;

public class SelectionEvent implements ActionListener {
	
	private final GuiApi gui;
	
	public SelectionEvent(GuiApi gui) {
		this.gui = gui;
	}

	@Override
	public void actionPerformed(ActionEvent e) {
		if(e.getSource().equals(gui.getZoneTypeSelection())) {
			String selected = (String)gui.getZoneTypeSelection().getSelectedItem();
			
			if(selected.equalsIgnoreCase("delegation-only")) {
				gui.getZoneOutputData().setText("type master;\ndelegation-only (yes);");
			} else if(selected.equalsIgnoreCase("forward")) {
				gui.getZoneOutputData().setText("type forward;\nforwarders {127.0.0.1 port 53;};");
			} else if(selected.equalsIgnoreCase("hint")) {
				gui.getZoneOutputData().setText("type hints;\nfile \"/etc/bind/named.conf.local\";");
			} else if(selected.equalsIgnoreCase("in-view")) {
				gui.getZoneOutputData().setText("in-view \"someone\";\nforwarders {127.0.0.1 port 53;};");
			} else if(selected.equalsIgnoreCase("master")) {
				gui.getZoneOutputData().setText("type master;\nfile \"/etc/bind/blocked.db\";");
			} else if(selected.equalsIgnoreCase("redirect")) {
				gui.getZoneOutputData().setText("type redirect;\nfile \"/etc/bind/custom-nx.zone\";");
			} else if(selected.equalsIgnoreCase("slave")) {
				gui.getZoneOutputData().setText("type slave;\nfile \"/etc/bind/blocked.db\";\nmasters port 1127 {192.168.1.18; 192.168.1.16 key zt-key;  mac:address port 1128;};");
			} else if(selected.equalsIgnoreCase("static-stub")) {
				gui.getZoneOutputData().setText("type static-stub;\nserver-addresses {127.0.0.1; mac::mac::0F};");
			}
		}
	}
	
	

}
