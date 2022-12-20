package utils;

import java.security.GeneralSecurityException;

public class HandshakeException extends Throwable {
    public HandshakeException(Exception e) {
        super(e);
    }

    public HandshakeException(String s) {
        super(s);
    }
}
