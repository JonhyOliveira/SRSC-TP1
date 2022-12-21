package utils;

import java.io.IOException;
import java.security.GeneralSecurityException;

public class HandshakeException extends Throwable {
    public HandshakeException(Exception e) {
        super(e);
    }

    public HandshakeException(String s) {
        super(s);
    }

    public HandshakeException(String s, Exception e) {
        super(s, e);
    }
}
