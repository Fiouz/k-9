package com.fsck.k9.authenticator;

import android.accounts.Account;
import android.accounts.AccountAuthenticatorActivity;
import android.accounts.AccountManager;
import android.app.Dialog;
import android.app.ProgressDialog;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Process;
import android.util.Log;
import android.view.View;
import android.widget.EditText;

import com.fsck.k9.K9;
import com.fsck.k9.R;

public class AuthenticatorActivity extends AccountAuthenticatorActivity
{

    public static final String PARAM_CONFIRMCREDENTIALS = "confirmCredentials";
    public static final String PARAM_USERNAME = "username";
    public static final String PARAM_PASSWORD = "password";
    public static final String PARAM_AUTHTOKEN_TYPE = "authtokenType";
    public static final String PARAM_FEATURES = "features";
    public static final String PARAM_HOST = "host";
    public static final String PARAM_PORT = "post";
    public static final String PARAM_PROTOCOL = "protocol";
    public static final String PARAM_SECURITY = "security";

    private static final int SDK_INT = Integer.parseInt(Build.VERSION.SDK);

    private final Handler mHandler = new Handler();
    private EditText mUsernameEdit;
    private EditText mPasswordEdit;
    private AccountManager mAccountManager;

    private String mAuthtokenType;
    private String mAuthtoken;

    @Override
    protected void onCreate(final Bundle savedInstanceState)
    {
        super.onCreate(savedInstanceState);

        mAuthtokenType = savedInstanceState.getString(PARAM_AUTHTOKEN_TYPE);

        mAccountManager = AccountManager.get(this);

        setContentView(R.layout.authenticator);
        mUsernameEdit = (EditText) findViewById(R.id.account_username);
        mPasswordEdit = (EditText) findViewById(R.id.account_password);
    }

    // override deprecated API to keep compatibility
    @Override
    protected Dialog onCreateDialog(int id)
    {
        // redirect to new API
        return onCreateDialog(id, null);
    }

    @Override
    protected Dialog onCreateDialog(final int id, final Bundle args)
    {
        final Dialog result;
        switch (id)
        {
        case R.id.dialog_progress:
        {
            result = new ProgressDialog(this);
        }
            break;
        default:
            result = null;
        }
        return result;
    }

    protected void showProgress()
    {
        if (SDK_INT < Build.VERSION_CODES.FROYO)
        {
            showDialog(R.id.dialog_progress);
        }
        else
        {
            showDialog(R.id.dialog_progress, null);
        }
    }

    protected void hideProgress()
    {
        dismissDialog(R.id.dialog_progress);
    }

    /**
     * To be invoked in the UI thread
     * 
     * @param view
     */
    public void handleLogin(final View view)
    {
        showProgress();
        checkLogin();
    }

    private void checkLogin()
    {
        // this is a dummy implementation for proof of concept purpose
        new Thread(new Runnable()
        {

            @Override
            public void run()
            {
                Process.setThreadPriority(Process.THREAD_PRIORITY_LOWEST);
                Log.i(K9.LOG_TAG, "TODO: check login/password against server");

                try
                {
                    Thread.sleep(5000);
                }
                catch (InterruptedException e)
                {
                    error();
                    return;
                }
                error();
            }

            private void error()
            {
                mHandler.post(new Runnable()
                {
                    @Override
                    public void run()
                    {
                        onAuthenticationResult(false);
                    }
                });
            }
        }).start();
    }

    public void onAuthenticationResult(final boolean valid)
    {
        hideProgress();
        final Bundle result = new Bundle();
        if (valid)
        {
            Log.w(K9.LOG_TAG, "TODO handle valid authentication");
            result.putInt(AccountManager.KEY_ERROR_CODE, AccountManager.ERROR_CODE_UNSUPPORTED_OPERATION);
            result.putString(AccountManager.KEY_ERROR_MESSAGE, "TODO: handle valid authentication");
        }
        else
        {
            result.putInt(AccountManager.KEY_ERROR_CODE, AccountManager.ERROR_CODE_UNSUPPORTED_OPERATION);
            result.putString(AccountManager.KEY_ERROR_MESSAGE, "TODO: handle invalid authentication");
        }
        setAccountAuthenticatorResult(result);
        // TODO enhance exit scenario
        finish();
    }

}
