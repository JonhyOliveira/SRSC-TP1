package server;

import utils.ConfigReader;
import utils.RTSSP_PacketType;
import utils.RTSSP_Socket;

import java.io.*;
import java.net.*;
import java.util.Arrays;
import java.util.Properties;

class hjStreamServer {

	static public void main( String []args ) throws Exception {

		int size;
		long time;
		long count = 0;

		Properties streamProperties = new Properties();
		streamProperties.load(hjStreamServer.class.getClassLoader().getResourceAsStream("server_configs/config.properties"));
		streamProperties.load(
				new ConfigReader(hjStreamServer.class.getClassLoader().getResourceAsStream("server_configs/box-cryptoconfig"),
						streamProperties.getProperty("broadcast"))
		);

		streamProperties.stringPropertyNames().forEach(s -> { System.out.printf("%-20s -> %s\n", s, streamProperties.getProperty(s)); });

		System.out.printf("Broadcasting to: '%s'\n", streamProperties.getProperty("broadcast"));

		DataInputStream stream = new DataInputStream(hjStreamServer.class.getClassLoader()
				.getResourceAsStream("movies/" + streamProperties.getProperty("movie")));
		byte[] buff = new byte[4096]; // can change if required
		byte[] movieName = streamProperties.getProperty("movie").getBytes();

		DatagramSocket s = new RTSSP_Socket(streamProperties);

		String[] remoteParts = streamProperties.getProperty("broadcast").split(":");
		InetSocketAddress addr =
				new InetSocketAddress( remoteParts[0], Integer.parseInt(remoteParts[1]));
		DatagramPacket p = new DatagramPacket(buff, buff.length, addr );

		Arrays.fill(buff, (byte) 0);
		buff[0] = (byte) RTSSP_PacketType.START.ordinal();
		System.arraycopy(movieName, 0, buff, 1, movieName.length);
		p.setData(buff, 0, movieName.length + 1);
		s.send(p);

		long t0 = System.nanoTime(); // current time
		long q0 = 0;
		while ( stream.available() > 0 ) {
			size = stream.readShort();
			time = stream.readLong();
			if ( count == 0 ) q0 = time; // ref time encoded
			count += 1;
			long t = System.nanoTime();
			Thread.sleep( Math.max(0, ((time-q0)-(t-t0))/1000000) );
			// send packet (with a frame payload)
			Arrays.fill(buff, (byte) 0);
			buff[0] = (byte) RTSSP_PacketType.DATA.ordinal();
			stream.readFully(buff, 1, size );
			p.setData(buff, 0, buff.length);
			s.send(p);
			//
			System.out.print( "." ); // only for debug
			// comment this for final experiment al observations
		}

		Arrays.fill(buff, (byte) 0);
		buff[0] = (byte) RTSSP_PacketType.END.ordinal();
		System.arraycopy(movieName, 0, buff, 1, movieName.length);
		p.setData(buff, 0, movieName.length + 1);
		s.send(p);

		// you must inlude now the call for PrintStats to print the
		// experimental observation of instrumentation variables

		System.out.println
				("DONE! all frames sent in this streaming transmission: "+count);

	}

}

