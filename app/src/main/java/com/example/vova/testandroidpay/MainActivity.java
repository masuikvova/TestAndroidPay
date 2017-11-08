package com.example.vova.testandroidpay;

import android.app.Activity;
import android.content.Intent;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.FrameLayout;
import android.widget.Toast;

import com.google.android.gms.common.api.ApiException;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.tasks.OnCompleteListener;
import com.google.android.gms.tasks.Task;
import com.google.android.gms.wallet.AutoResolveHelper;
import com.google.android.gms.wallet.CardRequirements;
import com.google.android.gms.wallet.IsReadyToPayRequest;
import com.google.android.gms.wallet.PaymentData;
import com.google.android.gms.wallet.PaymentDataRequest;
import com.google.android.gms.wallet.PaymentMethodTokenizationParameters;
import com.google.android.gms.wallet.PaymentsClient;
import com.google.android.gms.wallet.TransactionInfo;
import com.google.android.gms.wallet.Wallet;
import com.google.android.gms.wallet.WalletConstants;
import com.google.crypto.tink.subtle.Hex;

import org.json.JSONException;
import org.json.JSONObject;

import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class MainActivity extends AppCompatActivity {
    private static final String SECURITY_PROVIDER = "BC";
    private static final Charset DEFAULT_CHARSET = Charset.forName("UTF-8");
    private static final String ASYMMETRIC_KEY_TYPE = "EC";
    private static final String KEY_AGREEMENT_ALGORITHM = "ECDH";
    /**
     * OpenSSL name of the NIST P-126 Elliptic Curve
     */
    private static final String EC_CURVE = "prime256v1";
    private static final String SYMMETRIC_KEY_TYPE = "AES";
    private static final String SYMMETRIC_ALGORITHM = "AES/CTR/NoPadding";
    private static final byte[] SYMMETRIC_IV = Hex.decode("00000000000000000000000000000000");
    private static final int SYMMETRIC_KEY_BYTE_COUNT = 16;
    private static final String MAC_ALGORITHM = "HmacSHA256";
    private static final int MAC_KEY_BYTE_COUNT = 16;
    private static final byte[] HKDF_INFO = "Android".getBytes(DEFAULT_CHARSET);
    private static final byte[] HKDF_SALT = null /* equivalent to a zeroed salt of hashLen */;


    private Button payButton;
    private static final int LOAD_PAYMENT_DATA_REQUEST_CODE = 5034;

    private PaymentsClient mPaymentsClient;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        payButton = (Button) findViewById(R.id.button2);
        payButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                executeRequest();
            }
        });
        mPaymentsClient = Wallet.getPaymentsClient(this, new Wallet.WalletOptions.Builder()
                .setEnvironment(WalletConstants.ENVIRONMENT_TEST)
                .build());
        isReadyToPay();
    }

    private void isReadyToPay() {
        IsReadyToPayRequest request = IsReadyToPayRequest.newBuilder()
                .addAllowedPaymentMethod(WalletConstants.PAYMENT_METHOD_CARD)
                .addAllowedPaymentMethod(WalletConstants.PAYMENT_METHOD_TOKENIZED_CARD)
                .build();
        Task<Boolean> task = mPaymentsClient.isReadyToPay(request);
        task.addOnCompleteListener(
                new OnCompleteListener<Boolean>() {
                    public void onComplete(Task<Boolean> task) {
                        try {
                            boolean result = task.getResult(ApiException.class);
                            if (result) {
                                // Show Google as payment option.
                                payButton.setVisibility(View.VISIBLE);
                            } else {
                                // Hide Google as payment option.
                                payButton.setVisibility(View.GONE);
                            }
                        } catch (ApiException exception) {
                        }
                    }
                });
    }

    @Override
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        switch (requestCode) {
            case LOAD_PAYMENT_DATA_REQUEST_CODE:
                switch (resultCode) {
                    case Activity.RESULT_OK:
                        PaymentData paymentData = PaymentData.getFromIntent(data);
                        String token = paymentData.getPaymentMethodToken().getToken();

                        String dec = verifyThenDecrypt(token);

                        break;
                    case Activity.RESULT_CANCELED:
                        break;
                    case AutoResolveHelper.RESULT_ERROR:
                        Status status = AutoResolveHelper.getStatusFromIntent(data);
                        Log.i("PAY", "error: " + status);
                        // Log the status for debugging.
                        // Generally, there is no need to show an error to
                        // the user as the Google Payment API will do that.
                        break;
                    default:
                        // Do nothing.
                }
                break;
            default:
                // Do nothing.
        }
    }

    private void executeRequest() {
        PaymentDataRequest request = createPaymentDataRequest();
        if (request != null) {
            AutoResolveHelper.resolveTask(mPaymentsClient.loadPaymentData(request),
                    this,
                    LOAD_PAYMENT_DATA_REQUEST_CODE);
        }
    }

    private PaymentDataRequest createPaymentDataRequest() {


        PaymentDataRequest.Builder request =
                PaymentDataRequest.newBuilder()
                        .setTransactionInfo(
                                TransactionInfo.newBuilder()
                                        .setTotalPriceStatus(WalletConstants.TOTAL_PRICE_STATUS_FINAL)
                                        .setTotalPrice("1.00")
                                        .setCurrencyCode("UAH")
                                        .build())
                        .addAllowedPaymentMethod(WalletConstants.PAYMENT_METHOD_CARD)
                        .setCardRequirements(
                                CardRequirements.newBuilder()
                                        .addAllowedCardNetworks(
                                                Arrays.asList(
                                                        WalletConstants.CARD_NETWORK_AMEX,
                                                        WalletConstants.CARD_NETWORK_DISCOVER,
                                                        WalletConstants.CARD_NETWORK_VISA,
                                                        WalletConstants.CARD_NETWORK_MASTERCARD))
                                        .build());

        PaymentMethodTokenizationParameters params =
                PaymentMethodTokenizationParameters.newBuilder()
                        .setPaymentMethodTokenizationType(
                                WalletConstants.PAYMENT_METHOD_TOKENIZATION_TYPE_DIRECT)
                        .addParameter("publicKey", "BJ/085uIBjRq6dx03VrHGUJ03XMmrFktr8H5cPYU6C4g9txnhgaa1PsKMauMz4nffBVlgVOHA1abOV49bixhZg8=")
                        .build();

        request.setPaymentMethodTokenizationParameters(params);
        return request.build();
    }

    public String verifyThenDecrypt(String encryptedPayloadJson) {
        try {
            JSONObject object1 = new JSONObject(encryptedPayloadJson);
            JSONObject object = object1.getJSONObject("signedMessage");
            byte[] ephemeralPublicKeyBytes = Base64.decode(object.getString("ephemeralPublicKey"), Base64.NO_PADDING);
            byte[] encryptedMessage = Base64.decode(object.getString("encryptedMessage"), Base64.NO_PADDING);
            byte[] tag = Base64.decode(object.getString("tag"), Base64.NO_PADDING);

            String key = "BJ/085uIBjRq6dx03VrHGUJ03XMmrFktr8H5cPYU6C4g9txnhgaa1PsKMauMz4nffBVlgVOHA1abOV49bixhZg8=";


            // Decrypting the message.
            Cipher cipher = Cipher.getInstance(SYMMETRIC_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key.getBytes(), SYMMETRIC_KEY_TYPE), new IvParameterSpec(SYMMETRIC_IV));
            return new String(cipher.doFinal(encryptedMessage), DEFAULT_CHARSET);
        } catch (JSONException | NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException
                | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException("Failed verifying/decrypting message", e);
        }
    }

    /**
     * Fixed-timing array comparison.
     */
    public static boolean isArrayEqual(byte[] a, byte[] b) {
        if (a.length != b.length) {
            return false;
        }

        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }
}
