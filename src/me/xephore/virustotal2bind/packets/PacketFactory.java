package me.xephore.virustotal2bind.packets;

import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

public class PacketFactory {
	
	private final static PacketFactory factory = new PacketFactory();
	private ExecutorService service = Executors.newFixedThreadPool(10);
	
	private PacketFactory() {}
	
	public String[] sentPacket(final PacketContainer container) {
		
		if(service.isTerminated()) {
			service = Executors.newFixedThreadPool(10);
		}
		
		Future<String[]> fut = service.submit(new Callable<String[]>() {

			@Override
			public String[] call() {
				return container.execute();
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
