package me.xephore.virustotal2bind;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

import javax.swing.SwingUtilities;

import me.xephore.virustotal2bind.packets.DomainPacket;
import me.xephore.virustotal2bind.packets.IPAddressPacket;
import me.xephore.virustotal2bind.packets.Packet;
import me.xephore.virustotal2bind.packets.PacketFactory;

public class Main {

	public static void main(String[] args) {
		if(args.length == 0) {
			SwingUtilities.invokeLater(new Runnable() {

				@Override
				public void run() {
					Gui frame = new Gui("VirusTotal2Bind 2015 v(v0.0.2b) - the bind format converter!");
					frame.buildContainer();
					frame.createLayout();
					if(Configuration.getConfiguration().isGenerated()) {
						Configuration.getConfiguration().loadConfiguration();
						frame.startListeners();
					} else {
						Configuration.getConfiguration().createConfiguration();
						Configuration.getConfiguration().loadConfiguration();
					}
				}

			});
		} else if(args.length == 2) {
			
			if(Configuration.getConfiguration().isGenerated()) {
				Configuration.getConfiguration().loadConfiguration();
				//frame.startListeners();
			} else {
				System.out.println("please run this program for the first time in the gui!");
				return;
			}
			
			String url = args[0];
			File f = new File(args[1]);
			if(!f.exists()) {
				try {
					f.createNewFile();
				} catch (IOException e) {
					System.out.println("status: invalid file location, aborting!");
				}
			}
			if(DomainPacket.isUrl(url) || IPAddressPacket.isIp(url)) {
				System.out.println("status: url verified, now fetching from virustotal!");
				Packet packet1 = null;
				if(DomainPacket.isUrl(url)) {
					DomainPacket packet = new DomainPacket();
					packet1 = packet;
					packet.setDomainNameParam(url);
					System.out.println("fetch type: fetching as domain!");
				} else if(IPAddressPacket.isIp(url)) {	
					IPAddressPacket packet = new IPAddressPacket();
					packet1 = packet;
					packet.setIpAdressParam(url);
					System.out.println("fetch type: fetching as ip!");
				} else {
					System.out.println("status: unknown protocol, fetching aborted!");
				}
				String bind = PacketFactory.getFactory().sentPacket(packet1);
				System.out.println("status: fetching complete, now saving to file location " +  f.toString() + "!");
				try {
					FileWriter fw = new FileWriter(f, true);
					fw.write(bind);
					fw.flush();
					fw.close();
					System.out.println("status: save succeeded!");
				} catch(Exception e) {
					System.out.println("status: save failed!:");
					e.printStackTrace();
				}
			} else {
				System.out.println("status: url invalid!");
			}
		}
	}

}
