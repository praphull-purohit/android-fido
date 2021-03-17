package com.praphull.experiments.fido;

import android.app.PendingIntent;
import android.content.Intent;
import android.content.IntentSender;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;

import com.google.android.gms.common.util.Strings;
import com.google.android.gms.fido.Fido;
import com.google.android.gms.fido.fido2.Fido2ApiClient;
import com.google.android.gms.fido.fido2.api.common.AuthenticatorAssertionResponse;
import com.google.android.gms.fido.fido2.api.common.AuthenticatorAttestationResponse;
import com.google.android.gms.fido.fido2.api.common.AuthenticatorErrorResponse;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialCreationOptions;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialRequestOptions;
import com.google.android.gms.tasks.OnCompleteListener;
import com.google.android.gms.tasks.Task;
import com.google.android.gms.tasks.Tasks;

import java.util.concurrent.Callable;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

public class MainActivity extends AppCompatActivity {
    private final static String TAG = "MainActivity";
    private static final int REGISTER_REQUEST_CODE = 0;
    private static final int LOGIN_REQUEST_CODE = 1;

    // Create a new ThreadPoolExecutor with 2 threads for each processor on the
    // device and a 60 second keep-alive time.
    private static final int NUM_CORES = Runtime.getRuntime().availableProcessors();
    private static final ThreadPoolExecutor THREAD_POOL_EXECUTOR = new ThreadPoolExecutor(
            NUM_CORES * 2, NUM_CORES * 2, 60L, TimeUnit.SECONDS, new LinkedBlockingDeque<Runnable>());

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Log.d(TAG, "onCreate finished");
    }

    private void show(String message, Throwable t) {
        TextView tv = findViewById(R.id.resultMessage);
        tv.setText(message);
        if (t == null) {
            Log.d(TAG, message);
        } else {
            Log.w(TAG, message, t);
        }
    }

    private void show(String message) {
        show(message, null);
    }

    private Task<PublicKeyCredentialCreationOptions> getRegistrationOptions() {
        return Tasks.call(
                THREAD_POOL_EXECUTOR,
                new Callable<PublicKeyCredentialCreationOptions>() {
                    @Override
                    public PublicKeyCredentialCreationOptions call() throws Exception {
                        //TODO Make call to server to get options
                        return null;
                    }
                });
    }

    public void initiateRegistration(View v) {
        EditText phoneNumberInput = findViewById(R.id.phoneNumberInput);
        if (Strings.isEmptyOrWhitespace(phoneNumberInput.getText().toString())) {
            show("Enter phone number!");
        } else {

            Task<PublicKeyCredentialCreationOptions> registrationOptionsTask = getRegistrationOptions();
            registrationOptionsTask.addOnCompleteListener(task -> {
                PublicKeyCredentialCreationOptions options = task.getResult();
                if (options == null) {
                    Log.w(TAG, "Received null PublicKeyCredentialCreationOptions, exiting!");
                    return;
                }
                doRegistration(options);
            });
        }
    }

    private void doRegistration(PublicKeyCredentialCreationOptions options) {
        Fido2ApiClient fido2ApiClient = Fido.getFido2ApiClient(this.getApplicationContext());

        Task<PendingIntent> result = fido2ApiClient.getRegisterPendingIntent(options);

        result.addOnSuccessListener(pendingIntent -> {
            if (pendingIntent != null) {
                // Start a FIDO2 registration request.
                try {
                    startIntentSenderForResult(
                            pendingIntent.getIntentSender(),
                            REGISTER_REQUEST_CODE,
                            null, // fillInIntent
                            0,
                            0,
                            0
                    );
                } catch (IntentSender.SendIntentException e) {
                    show("Failed to register: " + e.getMessage(), e);
                }
            }
        });
        result.addOnFailureListener(e -> show("Failed to register: " + e.getMessage(), e));
    }

    private Task<PublicKeyCredentialRequestOptions> asyncGetSignRequest() {
        return Tasks.call(
                THREAD_POOL_EXECUTOR,
                new Callable<PublicKeyCredentialRequestOptions>() {
                    @Override
                    public PublicKeyCredentialRequestOptions call() {
                        //TODO Make call to server to get options
                        return null;
                    }
                });
    }

    public void login(View v) {
        Task<PublicKeyCredentialRequestOptions> getSignRequestTask = asyncGetSignRequest();
        getSignRequestTask.addOnCompleteListener(
                new OnCompleteListener<PublicKeyCredentialRequestOptions>() {
                    @Override
                    public void onComplete(@NonNull Task<PublicKeyCredentialRequestOptions> task) {
                        PublicKeyCredentialRequestOptions options = task.getResult();
                        if (options == null) {
                            Log.w(TAG, "Received null PublicKeyCredentialRequestOptions, exiting");
                            return;
                        }
                        doLogin(options);
                    }
                });
    }

    private void doLogin(PublicKeyCredentialRequestOptions options) {
        Fido2ApiClient fido2ApiClient = Fido.getFido2ApiClient(this.getApplicationContext());

        Task<PendingIntent> result = fido2ApiClient.getSignPendingIntent(options);

        result.addOnSuccessListener(pendingIntent -> {
            if (pendingIntent != null) {
                try {
                    startIntentSenderForResult(
                            pendingIntent.getIntentSender(),
                            LOGIN_REQUEST_CODE,
                            null,
                            0,
                            0,
                            0);
                } catch (IntentSender.SendIntentException e) {
                    show("Failed to login: " + e.getMessage(), e);
                }
            }
        });
        result.addOnFailureListener(e -> show("Failed to login: " + e.getMessage(), e));
    }

    @Override
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (resultCode == RESULT_OK) {
            if (data.hasExtra(Fido.FIDO2_KEY_ERROR_EXTRA)) {
                AuthenticatorErrorResponse response =
                        AuthenticatorErrorResponse.deserializeFromBytes(
                                data.getByteArrayExtra(Fido.FIDO2_KEY_ERROR_EXTRA));
                show("Received error response from Google Play Services FIDO2 API: " + response);
            } else if (requestCode == REGISTER_REQUEST_CODE) {
                show("Received register response from Google Play Services FIDO2 API");
                AuthenticatorAttestationResponse response =
                        AuthenticatorAttestationResponse.deserializeFromBytes(
                                data.getByteArrayExtra(Fido.FIDO2_KEY_RESPONSE_EXTRA));
                updateRegisterResponseToServer(response);
            } else if (requestCode == LOGIN_REQUEST_CODE) {
                show("Received login response from Google Play Services FIDO2 API");
                AuthenticatorAssertionResponse response =
                        AuthenticatorAssertionResponse.deserializeFromBytes(
                                data.getByteArrayExtra(Fido.FIDO2_KEY_RESPONSE_EXTRA));
                updateLoginResponseToServer(response);
            }
        } else {
            show("Operation failed!");
            Toast.makeText(
                    MainActivity.this,
                    "Operation failed, with resultCode " + resultCode,
                    Toast.LENGTH_SHORT)
                    .show();
        }
    }

    private void updateRegisterResponseToServer(AuthenticatorAttestationResponse response) {
        //TODO
    }

    private void updateLoginResponseToServer(AuthenticatorAssertionResponse response) {
        //TODO
    }
}