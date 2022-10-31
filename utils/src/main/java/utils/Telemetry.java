package utils;

import org.w3c.dom.css.CSSValueList;

import java.io.OutputStream;
import java.io.PrintStream;
import java.util.Date;
import java.util.Objects;
import java.util.Properties;

public final class Telemetry {

    private final Properties properties;
    private final String streamName;
    private Integer recordedFrames;
    private Long cipheredStreamSize;
    private Long startTime;
    private Long lastRecordedTime;
    private Long plainStreamSize;
    private Integer corruptedFrames;

    public Telemetry(String streamName, Properties streamProperties) {
        this.streamName = streamName;
        this.properties = new Properties();
        this.properties.putAll(streamProperties);
        this.recordedFrames = 0;
        this.cipheredStreamSize = 0L;
        this.plainStreamSize = 0L;
        this.startTime = null;
        this.corruptedFrames = 0;
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
    public String ciphersuite() {
        return properties.getProperty("ciphersuite");
    }

    /**
     * @return the key used to cipher data
     */
    public String key() {
        return properties.getProperty("key");
    }

    public String password() {
        return properties.getProperty("password");
    }

    /**
     * @return the size of the used key
     */
    public Integer keySize() {
        if (key() != null)
            return key().getBytes().length;
        else
            return null;
    }

    /**
     * @return the mechanism used for integrity check
     */
    public String integrityCheck() {
        return properties.getProperty("integrity");
    }

    /**
     * @return the number of frames that were recorded
     */
    public Integer recordedFrames() {
        return recordedFrames;
    }

    /**
     * @return the number of frames that were recorded as corrupted
     */
    public Integer corruptedFrames() {
        return corruptedFrames;
    }

    /**
     * @return the size of the stream, in KB
     */
    public Double streamSize() {
        return cipheredStreamSize.doubleValue() / 1000;
    }

    /**
     * @return the size of the stream, unencrypted, in KB
     */
    public Double rawSize() {
        return plainStreamSize.doubleValue() / 1000;
    }

    /**
     * @return how long we've been streaming for, in miliseconds
     */
    public Long elapsedTime() {
        if (lastRecordedTime != null)
            return lastRecordedTime - startTime;
        if (startTime != null)
            return System.currentTimeMillis() - startTime;
        return 0L;
    }

    /**
     * @return the rate of segments sent per second
     */
    public Double segmentRate()
    {
        return recordedFrames.doubleValue()/elapsedTime();
    }

    /**
     * @return the current throughput of this stream, in KBps
     */
    public Double throughput()
    {
        return cipheredStreamSize.doubleValue() / elapsedTime() / 1000D;
    }

    /**
     * @return the average size of a frame in Bytes
     */
    public Double averageFrameSize()
    {
        return cipheredStreamSize.doubleValue()/ recordedFrames();
    }

    /**
     * Starts measuring telemitry, if not started before
     */
    public void start()
    {
        if (this.startTime == null)
            this.startTime = System.currentTimeMillis();
    }

    public void recordFrame(Long frameSize, Long usefullSize)
    {
        cipheredStreamSize += frameSize;
        plainStreamSize += usefullSize;
        recordedFrames++;
        this.lastRecordedTime = System.currentTimeMillis();
    }

    public void recordCorruptedFrame()
    {
        corruptedFrames++;
        this.lastRecordedTime = System.currentTimeMillis();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) return true;
        if (obj == null || obj.getClass() != this.getClass()) return false;
        var that = (Telemetry) obj;
        return Objects.equals(this.streamName, that.streamName) &&
                Objects.equals(this.recordedFrames, that.recordedFrames) &&
                Objects.equals(this.cipheredStreamSize, that.cipheredStreamSize) &&
                Objects.equals(this.elapsedTime(), that.elapsedTime());
    }

    @Override
    public int hashCode() {
        return Objects.hash(streamName, recordedFrames, cipheredStreamSize);
    }

    @Override
    public String toString() {
        return "Metrics[" +
                "movieName=" + streamName + ", " +
                "framesSent=" + recordedFrames + ", " +
                "movieSize=" + cipheredStreamSize + ", " +
                "elapsedTime=" + elapsedTime() + ']';
    }

    public void print(PrintStream printStream) {
        printStream.printf("%n/-- Telemetry for '%s' stream --\\%n", streamName());
        printStream.println(" - Crypto Info - ");
        printStream.printf("Ciphersuite = '%s'%n", ciphersuite());
        if (Objects.nonNull(key())) {
            printStream.printf("Key: %s%n", key());
            printStream.printf("Key size: %d bytes%n", keySize());
        }
        else if (Objects.nonNull(password()))
            printStream.printf("Password: %s%n", password());
        if (Objects.nonNull(integrityCheck()))
            printStream.printf("Integrity checker = '%s'%n", integrityCheck());
        printStream.println(" - Stream Info - ");
        printStream.printf("%d frames", recordedFrames());
        if (corruptedFrames() > 0)
            printStream.printf(", of which, %d were corrupted", corruptedFrames());
        printStream.println(".");
        printStream.printf("%f bytes.%n", streamSize());
        if (recordedFrames() > 0) {
            printStream.printf("... average encrypted segment: ~%.2f bytes.%n", (float) cipheredStreamSize / recordedFrames());
            printStream.printf("... average decrypted segment: ~%.2f bytes.%n", (float) plainStreamSize / recordedFrames());
            printStream.printf("... plaintext-to-ciphertext ratio of ~%.2f%% in terms of size.%n", (float) cipheredStreamSize / plainStreamSize * 100);
        }
        printStream.printf("%d miliseconds elapsed.%n", elapsedTime());
        if (elapsedTime() > 0) {
            printStream.println("In the meanwhile....");
            printStream.printf("... %f segments per second.%n", segmentRate());
            printStream.printf("... with a throughput of %f KBps.%n", throughput());
            printStream.printf("... and averaging a frame size of ~%.2f bytes%n", averageFrameSize());
        }
    }

    public void writeTelemetry(OutputStream outputStream)
    {
        PrintStream printStream = new PrintStream(outputStream);

        // printStream.println("timestamp,movie,ciphersuite,key_size,integrity,frames,stream_size,stream_time");
        printStream.printf("%s,%s,%s,%d,%s,%d,%f,%d%n", new Date(), streamName(), ciphersuite(), keySize(), integrityCheck(),
                recordedFrames(), streamSize(), elapsedTime());
    }

}
