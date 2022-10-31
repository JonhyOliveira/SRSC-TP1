package server;

import utils.*;
import utils.crypto.CryptoException;
import utils.crypto.CryptoStuff;

import javax.crypto.Cipher;
import java.io.*;
import java.net.*;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;

class hjStreamServer {

	private static final boolean DEBUG = false;

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

		{
			String[] broadcastAddr = movieProperties.getProperty("broadcast").split(":");
			SocketAddress addr = new InetSocketAddress(broadcastAddr[0], Integer.parseInt(broadcastAddr[1]));

			broadcastStream(movieProperties.getProperty("name"), stream, addr, streamCryptoProperties);
		}

		cleanup.forEach(Runnable::run);
		stream.close();
	}

	/**
	 * Broadcasts a RT-stream over a secure UDP socket
	 * @param name the name of the stream
	 * @param stream the stream to broadcast
	 * @param broadcastAddr the broadcast address
	 * @param broadcastCryptoProps the cryptographic configurations. Should include AT LEAST the following properties:
	 *                             key, cyphersuite, iv. CAN also include integrity and mackey, if integrity is MAC-based.
	 * @throws IOException if there was an error reading from the stream or broadcasting
	 * @throws InterruptedException if there was an error while adjusting for Real time
	 * @throws CryptoException if there was cryptography-related error
	 */
	public static void broadcastStream(String name, DataInputStream stream, SocketAddress broadcastAddr,
									   Properties broadcastCryptoProps)
			throws IOException, InterruptedException, CryptoException {

		Telemetry telemetry = Telemetry.fromCryptoProperties(name, broadcastCryptoProps);

		RTSSP_Socket s = new RTSSP_Socket(broadcastCryptoProps);
		s.telemetrize(telemetry);

		byte[] streamName = name.getBytes();

		telemetry.start();
		s.send(RTSSP_Packet.compose(RTSSP_Packet.Type.START, streamName), broadcastAddr);

		long t0 = System.nanoTime(); // current time
		long q0 = 0;
		int frameSize;
		long frameTime;

		while ( stream.available() > 0 ) {
			frameSize = stream.readShort();
			frameTime = stream.readLong();
			if (telemetry.recordedFrames() == 0 ) q0 = frameTime; // ref time encoded
			long t = System.nanoTime();
			Thread.sleep( Math.max(0, ((frameTime-q0)-(t-t0))/1000000) );
			// compose & send packet
			s.send(RTSSP_Packet.compose(RTSSP_Packet.Type.DATA, stream.readNBytes(frameSize)), broadcastAddr);
			if (DEBUG)
				System.out.print( "." ); // only for debug
			else
				System.out.printf("\r%10d seconds elapsed, %10.3f kB received, %7.3f kBps", telemetry.elapsedTime() / 1000, telemetry.rawSize(), telemetry.throughput());
			// comment this for final experiment al observations
		}

		s.send(RTSSP_Packet.compose(RTSSP_Packet.Type.END, streamName), broadcastAddr);

		telemetry.print(System.err);
	}

}

