package com.fsck.k9.authenticator;

import android.accounts.AccountManager;
import android.os.Bundle;

public class AuthenticatorHelperException extends Exception {

    /**
     *
     */
    private static final long serialVersionUID = -7771793726004136939L;

    private final int mErrorCode;

    private final String mErrorMessage;

    /**
     * @param errorCode
     * @param errorMessage
     *            Never {@code null}.
     */
    public AuthenticatorHelperException(final int errorCode, final String errorMessage) {
        mErrorCode = errorCode;
        mErrorMessage = errorMessage;
    }

    /**
     * @param detailMessage
     * @param errorCode
     * @param errorMessage
     *            Never {@code null}.
     */
    public AuthenticatorHelperException(final String detailMessage, final int errorCode, final String errorMessage) {
        super(detailMessage);
        mErrorCode = errorCode;
        mErrorMessage = errorMessage;
    }

    /**
     * @param throwable
     * @param errorCode
     * @param errorMessage
     *            Never {@code null}.
     */
    public AuthenticatorHelperException(final Throwable throwable, final int errorCode, final String errorMessage) {
        super(throwable);
        mErrorCode = errorCode;
        mErrorMessage = errorMessage;
    }

    /**
     * @param detailMessage
     * @param throwable
     * @param errorCode
     * @param errorMessage
     *            Never {@code null}.
     */
    public AuthenticatorHelperException(final String detailMessage, final Throwable throwable, final int errorCode,
                                        final String errorMessage) {
        super(detailMessage, throwable);
        mErrorCode = errorCode;
        mErrorMessage = errorMessage;
    }

    public int getErrorCode() {
        return mErrorCode;
    }

    public String getErrorMessage() {
        return mErrorMessage;
    }

    /**
     * @return Never {@code null}.
     */
    public Bundle toBundle() {
        final Bundle bundle = new Bundle(2);
        bundle.putInt(AccountManager.KEY_ERROR_CODE, mErrorCode);
        bundle.putString(AccountManager.KEY_ERROR_MESSAGE, mErrorMessage);
        return bundle;
    }

}
