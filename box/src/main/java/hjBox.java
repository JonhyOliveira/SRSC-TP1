import utils.*;

import java.io.IOException;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;

class hjBox {

    private static final boolean DEBUG = false;

    private static InetSocketAddress parseSocketAddress(String socketAddress)
    {
        String[] split = socketAddress.split(":");
        String host = split[0];
        int port = Integer.parseInt(split[1]);
        return new InetSocketAddress(host, port);
    }

    private static Properties loadProperties() throws IOException {
        Properties props = new Properties();
        props.load(FileUtils.streamFromResourceOrPath("config.properties"));

        props.load(new XMLConfigReader(FileUtils.streamFromResourceOrPath(props.getProperty("conn-cryptoconfig")), props.getProperty("remote")));
        props.stringPropertyNames().stream()
                .map(s -> props.getProperty(s).trim().equalsIgnoreCase("NULL") ? s : null)
                .forEach(s -> { if (s != null) props.remove(s); });

        return props;
    }

    public static void main(String[] args) throws Exception {

        Properties streamProperties = loadProperties();

        streamProperties.stringPropertyNames().forEach(s -> { System.out.printf("%-20s -> %s\n", s, streamProperties.getProperty(s)); });

        SocketAddress inSocketAddress = parseSocketAddress(streamProperties.getProperty("remote"));
        Set<SocketAddress> outSocketAddresses = Arrays.stream(streamProperties.getProperty("localdelivery").split(","))
                .map(hjBox::parseSocketAddress)
                .collect(Collectors.toSet());

        RTSSP_Socket inSocket = new RTSSP_Socket(streamProperties, inSocketAddress);
        DatagramSocket outSocket = new DatagramSocket();
        byte[] buffer = new byte[RTSSP_Packet.BUFFER_SIZE];

        // wait for the start of a movie
        System.out.printf("Waiting for a movie stream to start @ %s\n", inSocketAddress);

        while (RTSSP_Packet.getPacketType(buffer) != RTSSP_Packet.Type.START) {
            buffer = inSocket.receive();
            System.out.print(". ");
        }

        String movieName = new String(buffer, 1, buffer.length - 1, StandardCharsets.UTF_8);
        Telemetry telemetry = Telemetry.fromCryptoProperties(movieName, streamProperties);
        inSocket.telemetrize(telemetry);
        telemetry.start();
        System.out.printf("Movie stream '%s' started\n", movieName);

        // stream the movie
        System.out.print("Waiting for data...");

        while (RTSSP_Packet.getPacketType(buffer) != RTSSP_Packet.Type.DATA) {
            buffer = inSocket.receive();
            System.out.print(".");
        }
        System.out.println();

        while (RTSSP_Packet.getPacketType(buffer) == RTSSP_Packet.Type.DATA)
        {
            for (SocketAddress outSocketAddress : outSocketAddresses)
                outSocket.send(new DatagramPacket(buffer, 1, buffer.length - 1, outSocketAddress));

            if (DEBUG)
                System.out.print("*");
            else
                System.out.printf("\r%10ds elapsed, %10.3f kB received, %7.3f kBps", telemetry.elapsedTime() / 1000, telemetry.rawSize(), telemetry.throughput());
            buffer = inSocket.receive();
        }

        telemetry.print(System.err);

    }
}
