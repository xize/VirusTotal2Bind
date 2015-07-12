package me.xephore.virustotal2bind.packets;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URL;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import javax.net.ssl.HttpsURLConnection;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

public class PacketFactory {
	
	private final static PacketFactory factory = new PacketFactory();
	private ExecutorService service = Executors.newFixedThreadPool(10);
	
	private PacketFactory() {}
	
	public String[] sentPacket(final Packet packet) {
		
		if(service.isTerminated()) {
			service = Executors.newFixedThreadPool(10);
		}
		
		Future<String[]> fut = service.submit(new Callable<String[]>() {

			@Override
			public String[] call() throws Exception {
					if(packet.getType() == PacketType.DOMAIN) {
						System.out.println("status: fetching data...");
						
						URL url = new URL(packet.getType().getProvider().toString() + "?domain="+packet.getParams()[0] + "&apikey="+packet.getParams()[1]);
						HttpsURLConnection con = (HttpsURLConnection) url.openConnection();
						con.setRequestMethod("GET");
						con.setDoOutput(true);
						InputStreamReader ireader = new InputStreamReader(con.getInputStream());
						BufferedReader breader = new BufferedReader(ireader);
						
						JSONParser parse = new JSONParser();
						JSONObject array = (JSONObject) parse.parse(breader);
						
						System.out.println("status: fetch completed, decoding data...");
						
						Decoder decoder = new PacketResolutionDecoder(array, packet.getParams()[0]);
						decoder.decode();
						
						Decoder decoder_detections = new PacketDetectionDecoder(array);
						decoder_detections.decode();
						
						System.out.println("status: decoding completed, closing connection!");
						
						String bind = (String)decoder.getResult();
						String detected = (String)decoder_detections.getResult();
						
						breader.close();
						ireader.close();
						con.disconnect();
						
						System.out.println("status: disconnected, idle...");
						
						return new String[] {bind, detected};
					} else if(packet.getType() == PacketType.IP) {
						System.out.println("status: fetching data...");
						
						URL url = new URL(packet.getType().getProvider().toString() + "?ip="+packet.getParams()[0] + "&apikey="+packet.getParams()[1]);
						HttpsURLConnection con = (HttpsURLConnection) url.openConnection();
						con.setRequestMethod("GET");
						
						InputStreamReader ireader = new InputStreamReader(con.getInputStream());
						BufferedReader breader = new BufferedReader(ireader);
						
						JSONParser parse = new JSONParser();
						JSONObject array = (JSONObject) parse.parse(breader);
						
						System.out.println("status: fetch completed, decoding data...");
						
						PacketResolutionDecoder decoder = new PacketResolutionDecoder(array, packet.getParams()[0]);
						decoder.decode();
						
						Decoder decoder_detections = new PacketDetectionDecoder(array);
						decoder_detections.decode();
						
						System.out.println("status: decoding completed, closing connection!");
						
						String bind = (String)decoder.getResult();
						String detected = (String)decoder_detections.getResult();
						breader.close();
						ireader.close();
						con.disconnect();
						
						return new String[] {bind, detected};
					}
					return null;
			}
		});
			try {
				String[] data = fut.get(10, TimeUnit.SECONDS);
				service.shutdown();
				return data;
			} catch (InterruptedException e) {
				e.printStackTrace();
			} catch (ExecutionException e) {
				e.printStackTrace();
			} catch (TimeoutException e) {
				e.printStackTrace();
			}
		return null;
	}
	
	public static PacketFactory getFactory() {
		return factory;
	}
	
}
