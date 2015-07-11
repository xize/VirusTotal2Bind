package me.xephore.virustotal2bind;

import javax.swing.SwingUtilities;

public class Main {

	public static void main(String[] args) {
		SwingUtilities.invokeLater(new Runnable() {

			@Override
			public void run() {
				Gui frame = new Gui("VirusTotal2Bind 2015 v(v0.0.1b) - the bind format converter!");
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
	}

}
