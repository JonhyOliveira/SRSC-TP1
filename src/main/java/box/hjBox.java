package box;/* hjBox, 22/23
 *
 * This is the implementation of a Box to receive streamed UDP packets
 * (with media segments as payloads encoding MPEG4 frames)
 * The code is inspired (in fact very similar) to the code presented,
 * available, used and discussed in Labs (Lab 2, Part I)
 *
 * You ca use this material as a starting point for your Box implementation
 * in TP1, according to the TP1 requirements
 */

import utils.ConfigReader;
import utils.RTSSP_PacketType;
import utils.RTSSP_Socket;

import java.io.IOException;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;

class hjBox {

    private static InetSocketAddress parseSocketAddress(String socketAddress)
    {
        String[] split = socketAddress.split(":");
        String host = split[0];
        int port = Integer.parseInt(split[1]);
        return new InetSocketAddress(host, port);
    }

    private static Properties loadProperties() throws IOException {
        Properties props = new Properties();
        props.load(hjBox.class.getClassLoader().getResourceAsStream("box_configs/config.properties"));

        props.load(new ConfigReader(hjBox.class.getClassLoader().getResourceAsStream("box_configs/box-cryptoconfig"), props.getProperty("remote")));

        return props;
    }

    public static void main(String[] args) throws Exception {

        // Need these variables for instrumentation metrics on
        // received and processed streams delivered to the
        // media player
        String movie; // name of received movie
        String csuite; // used cyphersuite to process the received stream
        String k;   // The key used, in Hexadecimal representation
        int ksize;  // The key size
        String hic; // Hash function used for integrity checks
        int ascsegments;    // average size of encrypted segments received
        int decsegments;    // average size of decrypted segments received
        int nf;     // number of received frames in a mmvie transmission
        int afs;    // average frame size in a movie transmission
        int ms;     // total size of the receved movie (all segments) in Kbytes
        int etm;    // total elapsed time of the received movie
        int frate;  // observed frame rate in segments/sec)
        int tput;   // observed throughput in the channel (in Kbytes/sec)
        int corruptedframes;   // Nr of corrupted frames discarded (not sent to the media player
        // can add more instrumentation variables considered as interesting

        Properties streamProperties = loadProperties();

        streamProperties.stringPropertyNames().forEach(s -> { System.out.printf("%-20s -> %s\n", s, streamProperties.getProperty(s)); });

        SocketAddress inSocketAddress = parseSocketAddress(streamProperties.getProperty("remote"));
        Set<SocketAddress> outSocketAddresses = Arrays.stream(streamProperties.getProperty("localdelivery").split(","))
                .map(hjBox::parseSocketAddress)
                .collect(Collectors.toSet());

        RTSSP_Socket inSocket = new RTSSP_Socket(streamProperties, inSocketAddress);
        DatagramSocket outSocket = new DatagramSocket();
        byte[] buffer = new byte[RTSSP_PacketType.BUFFER_SIZE];
        DatagramPacket inPacket = new DatagramPacket(buffer, buffer.length);
        // probably you need to use a larger buffer for the requirements of
        // TP1 - remember that you will receive datagrams with encrtypted
        // contents, so depending on the crypti configurations, the datagrams
        // will be bigger than the plaintext data in the initial example.

        // Not that this Box is always tryying to receive streams
        // You must modify this to contrl teh end of one received
        // movie) to obtain the related statistics (see PrintStats)

        // wait for the start of a movie
        System.out.printf("Waiting for a movie stream to start @ %s\n", inSocketAddress);

        while (buffer[0] != RTSSP_PacketType.START.ordinal()) {
            inPacket = new DatagramPacket(buffer, buffer.length);
            inSocket.receive(inPacket);
            System.out.printf("%s ", RTSSP_PacketType.values()[buffer[0]].toString());
        }

        System.out.printf("Movie stream '%s' started\n", new String(buffer, 1, inPacket.getLength() - 1, StandardCharsets.UTF_8));

        // stream the movie
        System.out.print("Waiting for data...");

        while (RTSSP_PacketType.values()[buffer[0]] != RTSSP_PacketType.DATA) {
            inSocket.receive(inPacket); // receive first data packet
            System.out.print(".");
        }
        System.out.println();

        while (RTSSP_PacketType.values()[buffer[0]] == RTSSP_PacketType.DATA)
        {
            for (SocketAddress outSocketAddress : outSocketAddresses)
                outSocket.send(new DatagramPacket(buffer, 1, buffer.length - 1, outSocketAddress));

            System.out.print("*");
            inSocket.receive(inPacket);
        }

        System.out.printf("Reached end of stream with %s packet.\n", RTSSP_PacketType.values()[buffer[0]].toString());

        // TODO: You must control/detect the end of a streamed movie to
            // call PrintStats to print the obtained statistics from
            // required instrumentation variables for experimental observations

            // PrintStats (......)
    }
}
