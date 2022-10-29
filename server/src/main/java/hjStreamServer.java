import utils.XMLConfigReader;
import utils.FileUtils;
import utils.RTSSP_Packet;
import utils.RTSSP_Socket;
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
			System.out.println("Stream crypto properties:");
			int x = streamCryptoProperties.stringPropertyNames().stream().mapToInt(String::length).max().orElse(20);
			streamCryptoProperties.stringPropertyNames()
					.forEach(p -> System.out.printf("%-" + x + "s -> %s\n", p, streamCryptoProperties.getProperty(p)));
		}

		DataInputStream stream = new DataInputStream(FileUtils.streamFromResourceOrPath(movieProperties.getProperty("file")));

		// decrypt file if needed
		if (fileCryptoProperties != null)
		{
			File decrypted = File.createTempFile("stream", ".decoded");
			File encrypted = new File(movieProperties.getProperty("file"));

			CryptoStuff.decrypt(movieProperties, encrypted, decrypted);

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

	public static void broadcastStream(String name, DataInputStream stream,
										SocketAddress broadcastAddr, Properties broadcastCryptoProps)
			throws IOException, InterruptedException, CryptoException {

		DatagramSocket s;
		if (broadcastCryptoProps != null)
			s = new RTSSP_Socket(broadcastCryptoProps);
		else
			s = new DatagramSocket();

		byte[] streamBuffer = new byte[RTSSP_Packet.BUFFER_SIZE];
		DatagramPacket p = new DatagramPacket(streamBuffer, streamBuffer.length, broadcastAddr);

		byte[] streamName = name.getBytes();

		Arrays.fill(streamBuffer, (byte) 0);
		RTSSP_Packet.compose(RTSSP_Packet.Type.START, streamName, p);
		s.send(p);

		long t0 = System.nanoTime(); // current time
		long q0 = 0;
		int frameSize;
		long frameTime;
		long frameCount = 0;

		while ( stream.available() > 0 ) {
			frameSize = stream.readShort();
			frameTime = stream.readLong();
			if ( frameCount == 0 ) q0 = frameTime; // ref time encoded
			frameCount += 1;
			long t = System.nanoTime();
			Thread.sleep( Math.max(0, ((frameTime-q0)-(t-t0))/1000000) );
			// compose & send packet
			Arrays.fill(streamBuffer, (byte) 0);
			RTSSP_Packet.compose(RTSSP_Packet.Type.DATA, stream.readNBytes(frameSize), p);
			s.send(p);
			System.out.print( "." ); // only for debug
			// comment this for final experiment al observations
		}

		Arrays.fill(streamBuffer, (byte) 0);
		RTSSP_Packet.compose(RTSSP_Packet.Type.END, streamName, p);
		s.send(p);
	}

}

