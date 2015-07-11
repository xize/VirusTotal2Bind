package me.xephore.virustotal2bind;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;

public class Configuration {

	private String key;
	
	private final static Configuration conf = new Configuration();
	
	protected Configuration() {}
	
	public void createConfiguration() {
		File dir = getDataFolder();
		dir.mkdir();
		File f = new File(dir + File.separator + "data.key");
		try {
			f.createNewFile();
			FileWriter fw = new FileWriter(f, true);
			fw.write("# please fill in your virustotal api key in order to use this program again! #\r\n");
			fw.write("api-key: <yourkey>");
			fw.flush();
			fw.close();
			Runtime.getRuntime().exec("notepad.exe " + f);
			Runtime.getRuntime().exit(0);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	public void loadConfiguration() {
		File f = new File(getDataFolder() + File.separator + "data.key");
		try {
			FileReader r = new FileReader(f);
			BufferedReader bf = new BufferedReader(r);
			bf.readLine();
			this.key = bf.readLine().split(": ")[1];
			bf.close();
			r.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public boolean isGenerated() {
		return getDataFolder().isDirectory();
	}
	
	public String getApiKey() {
		return key;
	}
	
	public File getDataFolder() {
		return new File(System.getenv("APPDATA") + File.separator + "VirusTotal2Bind");
	}
	
	public static Configuration getConfiguration() {
		return conf;
	}
	
}
