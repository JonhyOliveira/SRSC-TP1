package server;

import utils.*;
import utils.crypto.CryptoException;
import utils.crypto.CryptoStuff;

import java.io.*;
import java.net.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;

public final class StreamServer implements Runnable, StreamingServer {

	private static final boolean DEBUG = Boolean.getBoolean(System.getProperty("DEBUG"));

	public static Properties loadConfig() throws IOException {
		Properties properties = new Properties();
		properties.load(FileUtils.streamFromResourceOrPath("config.properties"));
		return properties;
	}

	public static Properties loadCryptoConfig(String fileName, String tag) throws IOException {
		Properties cryptoConfig = null;

		if (fileName != null)
		{
			cryptoConfig = new Properties();
			cryptoConfig.load(new XMLConfigReader(FileUtils.streamFromResourceOrPath(fileName), tag));
		}

		return cryptoConfig;
	}

	public static void main( String []args ) throws Exception {

		List<Runnable> cleanup = new LinkedList<>(); // actions executed at the end of the program

		// load configurations
		Properties
				movieProperties = loadConfig(),
				fileCryptoProperties = loadCryptoConfig(movieProperties.getProperty("file-cryptoconfig"),
						new File(movieProperties.getProperty("file")).getName()),
				streamCryptoProperties = loadCryptoConfig(movieProperties.getProperty("conn-cryptoconfig"),
						movieProperties.getProperty("broadcast"));

		if (streamCryptoProperties != null)
		{
			streamCryptoProperties.stringPropertyNames().stream()
					.map(s -> streamCryptoProperties.getProperty(s).trim().equalsIgnoreCase("NULL") ? s : null)
					.forEach(s -> { if (s != null) streamCryptoProperties.remove(s); });

			System.out.println("Stream crypto properties:");
			int x = streamCryptoProperties.stringPropertyNames().stream().mapToInt(String::length).max().orElse(20);
			streamCryptoProperties.stringPropertyNames()
					.forEach(p -> System.out.printf("%-" + x + "s -> %s\n", p, streamCryptoProperties.getProperty(p)));
		}

		DataInputStream stream = new DataInputStream(FileUtils.streamFromResourceOrPath(movieProperties.getProperty("file")));

		// decrypt file if needed
		if (fileCryptoProperties != null)
		{
			fileCryptoProperties.stringPropertyNames().stream()
					.map(s -> fileCryptoProperties.getProperty(s).trim().equalsIgnoreCase("NULL") ? s : null)
					.forEach(s -> { if (s != null) fileCryptoProperties.remove(s); });

			System.out.printf("'%s' file crypto properties:\n", movieProperties.getProperty("file"));
			int x = fileCryptoProperties.stringPropertyNames().stream().mapToInt(String::length).max().orElse(20);
			fileCryptoProperties.stringPropertyNames()
					.forEach(p -> System.out.printf("%-" + x + "s -> %s\n", p, fileCryptoProperties.getProperty(p)));

			File decrypted = File.createTempFile("stream", ".decoded");
			File encrypted = new File(movieProperties.getProperty("file"));

			CryptoStuff.decrypt(fileCryptoProperties, encrypted, decrypted);

			stream = new DataInputStream(new FileInputStream(decrypted));
			cleanup.add(decrypted::delete);
		}

		String[] broadcastAddr = movieProperties.getProperty("broadcast").split(":");
		SocketAddress addr = new InetSocketAddress(broadcastAddr[0], Integer.parseInt(broadcastAddr[1]));

		Stream stream1 = new Stream(movieProperties.getProperty("name"), stream, addr, streamCryptoProperties);
		stream1.run();
		stream1.writeStatistics(System.out);

		cleanup.forEach(Runnable::run);
		stream.close();
	}

	private static final ConcurrentMap<SocketAddress, StreamServer> streamServers = new ConcurrentHashMap<>();

	public static StreamServer getInstance(SocketAddress addr) {
		if (!streamServers.containsKey(addr))
			streamServers.put(addr, new StreamServer(addr));

		return streamServers.get(addr);
	}

	private SocketAddress broadcastAddr;
	private BlockingQueue<StreamInfo> streamQueue;
	public StreamServer(SocketAddress broadcastAddr) {
		this.broadcastAddr = broadcastAddr;
		this.streamQueue = new LinkedBlockingQueue<>();
	}

	/**
	 * Queues a stream to be broadcasted through the broadcast address associated with this server
	 * @return the position of the item in the queue, 1 being the front of the queue
	 */
	@Override
	public int stream(StreamInfo info) {
		streamQueue.add(info);

		return streamQueue.size();
	}

	@Override
	public SocketAddress getBroadcastAddr() {
		return broadcastAddr;
	}

	@Override
	public void run() {
		// try to take an item from the queue for a limited amount of time, if unsuccessfull, terminate execution

		try {
			StreamInfo streamInfo;
			while ((streamInfo = streamQueue.poll(20, TimeUnit.SECONDS)) != null) {
					new Stream(streamInfo, getBroadcastAddr()).run();
			}
		} catch (InterruptedException e) {
			throw new RuntimeException(e);
		}

		streamServers.remove(broadcastAddr);
	}

	public static class Stream implements Runnable {

		private final boolean DEBUG = Boolean.getBoolean(System.getProperty("DEBUG"));

		private final Telemetry results;
		private final String streamID;
		private final DataInputStream stream;
		private final SocketAddress broadcastAddr;
		private final Properties broadcastCryptoProps;

		/**
		 * A server to broadcast a RT-stream over a secure UDP socket with configurable security
		 * @param streamID the string identifying this stream
		 * @param stream the stream to broadcast. The stream data is to be composed of segments of bytes separated by newline
		 *               characters. See
		 * @param broadcast the broadcast address
		 * @param broadcastCryptoProps the cryptographic configurations. Should include AT LEAST the following properties:
		 *                             key, cyphersuite, iv. CAN also include integrity and mackey, if integrity is MAC-based.
		 */
		public Stream(String streamID, DataInputStream stream, SocketAddress broadcast, Properties broadcastCryptoProps)
		{
			this.streamID = streamID;
			this.stream = stream;
			this.broadcastAddr = broadcast;
			this.broadcastCryptoProps = broadcastCryptoProps;

			results = new Telemetry(streamID, broadcastCryptoProps);
		}

		public Stream(StreamInfo streamInfo, SocketAddress broadcast) {
			this(streamInfo.getStreamID(), streamInfo.getStreamData(), broadcast, streamInfo.getCryptoProperties());
		}

		@Override
		public void run() {

			try (RTSSP_Socket s = new RTSSP_Socket(broadcastCryptoProps)) {
				s.telemetrize(results);

				byte[] ID = streamID.getBytes();

				results.start();
				s.send(RTSSP_Packet.compose(RTSSP_Packet.Type.START, ID), broadcastAddr);

				long t0 = System.nanoTime(); // current time
				long q0 = 0;
				int frameSize;
				long frameTime;

				while (stream.available() > 0) {
					frameSize = stream.readShort();
					frameTime = stream.readLong();
					if (results.recordedFrames() == 0) q0 = frameTime; // ref time encoded
					long t = System.nanoTime();
					Thread.sleep(Math.max(0, ((frameTime - q0) - (t - t0)) / 1000000));
					// compose & send packet
					s.send(RTSSP_Packet.compose(RTSSP_Packet.Type.DATA, stream.readNBytes(frameSize)), broadcastAddr);
					if (DEBUG)
						System.out.printf("\rStream '%s': %10d seconds elapsed, %10.3f kB received, %7.3f kBps", streamID, results.elapsedTime() / 1000, results.rawSize(), results.throughput());
					// comment this for final experiment al observations
				}

				s.send(RTSSP_Packet.compose(RTSSP_Packet.Type.END, ID), broadcastAddr);

				try {
					results.writeTelemetry(new FileOutputStream("logfile_server.csv", true));
				} catch (FileNotFoundException e) {
					throw new RuntimeException(e);
				}
			} catch (IOException | CryptoException | InterruptedException e) {
				e.printStackTrace();
			}
		}

		public void writeStatistics(OutputStream outputStream) {
			results.writeTelemetry(outputStream);
		}

	}
}

