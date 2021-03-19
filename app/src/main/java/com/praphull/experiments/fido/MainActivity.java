package com.praphull.experiments.fido;

import android.app.PendingIntent;
import android.content.Intent;
import android.content.IntentSender;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.EditText;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.google.android.gms.common.util.Strings;
import com.google.android.gms.fido.Fido;
import com.google.android.gms.fido.fido2.Fido2ApiClient;
import com.google.android.gms.fido.fido2.api.common.AuthenticatorAssertionResponse;
import com.google.android.gms.fido.fido2.api.common.AuthenticatorAttestationResponse;
import com.google.android.gms.fido.fido2.api.common.AuthenticatorErrorResponse;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialCreationOptions;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialRequestOptions;
import com.google.android.gms.tasks.Task;
import com.praphull.experiments.fido.client.Base64ExtKt;
import com.praphull.experiments.fido.client.FidoHttpClient;
import com.praphull.experiments.fido.client.model.Credential;

import java.io.IOException;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import okhttp3.Response;

public class MainActivity extends AppCompatActivity {
    private final static String TAG = "MainActivity";
    private static final int REGISTER_REQUEST_CODE = 0;
    private static final int LOGIN_REQUEST_CODE = 1;

    // Create a new ThreadPoolExecutor with 2 threads for each processor on the
    // device and a 60 second keep-alive time.
    private static final int NUM_CORES = Runtime.getRuntime().availableProcessors();
    private static final ThreadPoolExecutor THREAD_POOL_EXECUTOR = new ThreadPoolExecutor(
            NUM_CORES * 2, NUM_CORES * 2, 60L, TimeUnit.SECONDS, new LinkedBlockingDeque<Runnable>());

    private static final FidoHttpClient httpClient = new FidoHttpClient();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Log.d(TAG, "onCreate finished");
    }

    private void show(String message, Throwable t) {
        Toast.makeText(MainActivity.this, message, Toast.LENGTH_LONG).show();
        if (t == null) {
            Log.d(TAG, message);
        } else {
            Log.w(TAG, message, t);
        }
    }

    private void show(String message) {
        show(message, null);
    }

    public void initiateRegistration(View v) {
        EditText phoneNumberInput = findViewById(R.id.phoneNumberInput);
        if (Strings.isEmptyOrWhitespace(phoneNumberInput.getText().toString())) {
            show("Enter phone number!");
        } else {
            //TODO: Remove hardcoding of user id
            Task<Response> registrationOptionsTask = httpClient.getRegistrationOptions(1L, THREAD_POOL_EXECUTOR);
            registrationOptionsTask.addOnCompleteListener(task -> {
                Response response = task.getResult();
                if (response == null) {
                    Log.w(TAG, "Received null response for , exiting!");
                    return;
                }

                if (!response.isSuccessful() || response.body() == null) {
                    Log.w(TAG, "Received invalid response for PublicKeyCredentialCreationOptions, exiting!");
                    try {
                        Log.d(TAG, "Response (status " + response.code() + "): " + response.body().string());
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                    return;
                }
                PublicKeyCredentialCreationOptions options =
                        httpClient.parsePublicKeyCredentialCreationOptions(Objects.requireNonNull(response.body()));

                doRegistration(options);
            });
        }
    }

    private void doRegistration(PublicKeyCredentialCreationOptions options) {
        Fido2ApiClient fido2ApiClient = Fido.getFido2ApiClient(this.getApplicationContext());

        Log.d(TAG, "doRegistration: Inside");
        Task<PendingIntent> result = fido2ApiClient.getRegisterPendingIntent(options);

        result.addOnSuccessListener(pendingIntent -> {
            Log.d(TAG, "doRegistration: onSuccess");
            if (pendingIntent != null) {
                // Start a FIDO2 registration request.
                try {
                    Log.d(TAG, "doRegistration: Starting intent");
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

    public void login(View v) {
        //TODO: Remove hardcoding of user id
        Task<PublicKeyCredentialRequestOptions> getSignRequestTask =
                httpClient.loginRequest(1L, null, THREAD_POOL_EXECUTOR);
        getSignRequestTask.addOnCompleteListener(task -> {
            PublicKeyCredentialRequestOptions options = task.getResult();
            if (options == null) {
                Log.w(TAG, "Received null PublicKeyCredentialRequestOptions, exiting");
                return;
            }
            doLogin(options);
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
            show("Operation failed, with resultCode " + resultCode);
        }
    }

    private void updateRegisterResponseToServer(AuthenticatorAttestationResponse response) {
        Log.d(TAG, "updateRegisterResponseToServer response: " + response);
        Log.d(TAG, "updateRegisterResponseToServer: att: " + Base64ExtKt.toBase64(response.getAttestationObject()));
        //TODO: Remove hardcoding of user id
        Task<List<Credential>> result =
                httpClient.registerResponse(1L, response, THREAD_POOL_EXECUTOR);
        if (result == null) {
            Log.w(TAG, "Received null task in updateRegisterResponseToServer, exiting");
            return;
        }

        result.addOnCompleteListener(task -> {
            List<Credential> credentials = task.getResult();
            Log.d(TAG, "updateRegisterResponseToServer succeeded with result: " + credentials);
        });
        result.addOnFailureListener(e -> show("Failed to update registration response on server: " + e.getMessage(), e));
    }

    private void updateLoginResponseToServer(AuthenticatorAssertionResponse response) {
        Log.d(TAG, "updateLoginResponseToServer response: " + response);
        //TODO
    }
}