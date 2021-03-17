package com.praphull.experiments.fido;

import android.app.PendingIntent;
import android.content.IntentSender;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import com.google.android.gms.common.util.Strings;
import com.google.android.gms.fido.Fido;
import com.google.android.gms.fido.fido2.Fido2ApiClient;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialCreationOptions;
import com.google.android.gms.tasks.Task;
import com.google.android.gms.tasks.Tasks;

import java.util.concurrent.Callable;
import java.util.concurrent.Executors;

public class MainActivity extends AppCompatActivity {
    private final static String TAG = "MainActivity";
    private static final int REGISTER_REQUEST_CODE = 0;

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
            Log.d(TAG, message, t);
        }
    }

    private void show(String message) {
        show(message, null);
    }

    private Task<PublicKeyCredentialCreationOptions> getRegistrationOptions() {
        return Tasks.call(
                Executors.newSingleThreadExecutor(),
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
                    Log.d(TAG, "Received null PublicKeyCredentialCreationOptions, exiting");
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
}