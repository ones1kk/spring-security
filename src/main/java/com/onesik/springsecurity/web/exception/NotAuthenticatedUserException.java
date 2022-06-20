package com.onesik.springsecurity.web.exception;

public class NotAuthenticatedUserException extends RuntimeException {

    public NotAuthenticatedUserException() {
        super();
    }

    public NotAuthenticatedUserException(String message) {
        super(message);
    }

    public NotAuthenticatedUserException(String message, Throwable cause) {
        super(message, cause);
    }

    public NotAuthenticatedUserException(Throwable cause) {
        super(cause);
    }

    protected NotAuthenticatedUserException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
