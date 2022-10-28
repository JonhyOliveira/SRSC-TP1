package server;

import java.io.PrintStream;
import java.util.Objects;
import java.util.Properties;

public final class Telemetry {

    private final String streamName;
    private final String cyphersuite;
    private final String key;
    private final String integrityCheck;
    private Integer framesSent;
    private Long streamSize;
    private Long startTime;
    private Long lastSendTime;

    public Telemetry(String streamName, String cyphersuite, String key, String integrityCheck) {
        this.streamName = streamName;
        this.cyphersuite = cyphersuite;
        this.key = key;
        this.integrityCheck = integrityCheck;
        this.framesSent = 0;
        this.streamSize = 0L;
        this.startTime = null;
    }

    /**
     * @return the name of the stream being metered
     */
    public String streamName() {
        return streamName;
    }

    /**
     * @return the cyphersuite used to cypher data
     */
    public String cyphersuite() {
        return cyphersuite;
    }

    /**
     * @return the key used to cipher data
     */
    public String key() {
        return key;
    }

    /**
     * @return the size of the used key
     */
    public Integer keySize() {
        return key.getBytes().length;
    }

    /**
     * @return the mechanism used for integrity check
     */
    public String integrityCheck() {
        return integrityCheck;
    }

    /**
     * @return the number of sent frames
     */
    public Integer framesSent() {
        return framesSent;
    }

    /**
     * @return the size of the stream, in KBs
     */
    public Double streamSize() {
        return streamSize.doubleValue() / 1000;
    }

    /**
     * @return how long we've been streaming for, in miliseconds
     */
    public Long elapsedTime() {
        if (lastSendTime != null)
            return lastSendTime - startTime;
        if (startTime != null)
            return System.currentTimeMillis() - startTime;
        return 0L;
    }

    /**
     * @return the rate of segments sent per second
     */
    public Double segmentRate()
    {
        return framesSent.doubleValue()/elapsedTime();
    }

    /**
     * @return the current throughput of this stream, in Bps
     */
    public Double throughput()
    {
        return streamSize.doubleValue() /elapsedTime();
    }

    /**
     * @return the average size of a frame in Bytes
     */
    public Double averageFrameSize()
    {
        return streamSize.doubleValue()/framesSent();
    }

    /**
     * Starts measuring telemitry, if not started before
     */
    public void startedTelemitry()
    {
        if (this.startTime != null)
            this.startTime = System.currentTimeMillis();
    }

    public void sentFrame(Long frameSize)
    {
        streamSize += frameSize;
        framesSent++;
        this.lastSendTime = System.currentTimeMillis();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) return true;
        if (obj == null || obj.getClass() != this.getClass()) return false;
        var that = (Telemetry) obj;
        return Objects.equals(this.streamName, that.streamName) &&
                Objects.equals(this.cyphersuite, that.cyphersuite) &&
                Objects.equals(this.key, that.key) &&
                Objects.equals(this.integrityCheck, that.integrityCheck) &&
                Objects.equals(this.framesSent, that.framesSent) &&
                Objects.equals(this.streamSize, that.streamSize) &&
                Objects.equals(this.elapsedTime(), that.elapsedTime());
    }

    @Override
    public int hashCode() {
        return Objects.hash(streamName, cyphersuite, key, integrityCheck, framesSent, streamSize);
    }

    @Override
    public String toString() {
        return "Metrics[" +
                "movieName=" + streamName + ", " +
                "cyphersuite=" + cyphersuite + ", " +
                "key=" + key + ", " +
                "integrityCheck=" + integrityCheck + ", " +
                "framesSent=" + framesSent + ", " +
                "movieSize=" + streamSize + ", " +
                "elapsedTime=" + elapsedTime() + ']';
    }

    public void print(PrintStream printStream) {
        printStream.println("... Telemetry for stream %s ...".formatted(this.streamName));
        printStream.println();
        printStream.println(" - Crypto Info - ");
        printStream.println("Cyphersuite = '%s'".formatted(cyphersuite()));
        printStream.println("Key = '%s' => %d bytes".formatted(key(), keySize()));
        printStream.println("Integrity checker = '%s'".formatted(integrityCheck()));
        printStream.println();
        printStream.println(" - Stream Info - ");
        printStream.println("%d frames sent.".formatted(framesSent()));
        printStream.println("%f bytes sent".formatted(streamSize()));
        printStream.println("%d miliseconds elapsed.".formatted(elapsedTime()));
        if (elapsedTime() > 0) {
            printStream.println("\tIn the meanwhile....");
            printStream.println("\t... sent %f segments per second.".formatted(segmentRate()));
            printStream.println("\t... with a hroughput of %f KBps.".formatted(throughput()));
            printStream.println("\t... and averaging a frame size of ~%.2f bytes".formatted(averageFrameSize()));
        }
    }

    public static Telemetry fromProperties(Properties properties)
    {
        return new Telemetry(properties.getProperty("movie"), properties.getProperty("cyphersuite"),
                properties.getProperty("key"), properties.getProperty("integrity"));
    }

}
