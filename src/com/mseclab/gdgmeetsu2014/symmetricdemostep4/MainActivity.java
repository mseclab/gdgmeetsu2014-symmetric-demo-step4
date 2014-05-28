package com.mseclab.gdgmeetsu2014.symmetricdemostep4;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import com.mseclab.gdgmeetsu2014.symmetricdemostep4.R;

import android.os.Build;
import android.os.Bundle;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.text.InputType;
import android.util.Base64;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;

public class MainActivity extends Activity {

	private TextView outView;
	private EditText mInData;
	private EditText mOutData;

	private final static String TAG = "GDG";
	private final static String TRANSFORMATION = "AES/CBC/PKCS5Padding";
	private final static int KEY_LEN = 128;

	// NEVED DO THIS....
	private static final byte[] IV = "1234567890abcdef".getBytes();
	private static final byte[] SALT = "abcdef".getBytes();

	
	private static final int NUM_OF_ITERATIONS = 1000;
	private static SecretKey key = null;

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);
		outView = (TextView) findViewById(R.id.out_view);
		mInData = (EditText) findViewById(R.id.inDataText);
		mOutData = (EditText) findViewById(R.id.outDataText);

		// Set Action Bar Title
		getActionBar().setTitle(R.string.action_bar_title);
		getActionBar().setSubtitle(R.string.action_bar_subtitle);
	}

	@Override
    protected void onResume() {
        super.onResume();		
        // Ask user password
		askPassword();
    }

	@Override
    protected void onPause() {
        key = null;
    	super.onPause();
    }
	
	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.main, menu);
		return true;
	}

	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
		// Handle presses on the action bar items
		switch (item.getItemId()) {
		case R.id.action_discard:
			outView.setText("");
			return true;
		default:
			return super.onOptionsItemSelected(item);
		}
	}

	public boolean isKeyReady() {
		if (key == null)
			return false;
		else
			return true;
	}

	private void askPassword() {
		AlertDialog.Builder alert = new AlertDialog.Builder(this);

		alert.setTitle("Password Required");
		alert.setMessage("Please insert a password");

		// Set an EditText view to get user input
		final EditText input = new EditText(this);
		input.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
		alert.setView(input);

		alert.setPositiveButton("Ok", new DialogInterface.OnClickListener() {
			public void onClick(DialogInterface dialog, int whichButton) {
				String password = input.getText().toString();
				debug(password);
				initPBEKey(password);
			}
		});

		alert.setNegativeButton("Cancel", new DialogInterface.OnClickListener() {
			public void onClick(DialogInterface dialog, int whichButton) {
				finish();
			}
		});

		alert.show();
	}

	private void initPBEKey(String password) {
		debug("Password: " + password);
		KeySpec keySpec = new PBEKeySpec(password.toCharArray(), SALT, NUM_OF_ITERATIONS, KEY_LEN);
		SecretKeyFactory secretKeyFactory = null;
		try {
			
			if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT)
				// Use compatibility key factory -- only uses lower 8-bits of passphrase chars
				secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1And8bit");
			else if (Build.VERSION.SDK_INT >= 10)
				// Traditional key factory. Will use lower 8-bits of passphrase chars on
			   	// older Android versions (API level 18 and lower) and all available bits
			   	// on KitKat and newer (API level 19 and higher).
				secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
			else // FIX for Android 8,9
				secretKeyFactory = SecretKeyFactory.getInstance("PBEWITHSHAAND128BITAES-CBC-BC");

		} catch (NoSuchAlgorithmException e) {
			debug("Algorithm not available: " + e.getMessage());
			return;
		}

		try {
			key = secretKeyFactory.generateSecret(keySpec);
		} catch (InvalidKeySpecException e) {
			debug("Invalid Key Specification: " + e.getMessage());
			return;
		}
		debug("Key = " + Base64.encodeToString(key.getEncoded(), Base64.DEFAULT));
	}

	public void onEncryptClick(View view) {
		byte[] input = mInData.getText().toString().getBytes();
		byte[] output = cipherData(Cipher.ENCRYPT_MODE, input);

		if (output != null) {
			String outputBase64 = Base64.encodeToString(output, Base64.DEFAULT);
			mOutData.setText(outputBase64);
		}

	}

	public void onDecryptClick(View view) {
		byte[] input = Base64.decode(mOutData.getText().toString().getBytes(), Base64.DEFAULT);
		byte[] output = cipherData(Cipher.DECRYPT_MODE, input);

		if (output != null) {
			mInData.setText(new String(output));
		}

	}

	private byte[] cipherData(int opMode, byte[] input) {
		if (!isKeyReady()) {
			debug("Key not ready...");
			return null;
		}

		// Get Cipher Instance
		Cipher cipher = null;
		try {
			cipher = Cipher.getInstance(TRANSFORMATION);
		} catch (NoSuchAlgorithmException e) {
			debug("Algorithm not available");
			return null;
		} catch (NoSuchPaddingException e) {
			debug("Padding not available");
			return null;
		}

		// Init cipher
		try {
			SecretKeySpec finalKey = new SecretKeySpec(key.getEncoded(), "AES");
			//cipher.init(opMode, key, new IvParameterSpec(IV));
			cipher.init(opMode, finalKey, new IvParameterSpec(IV));
		} catch (InvalidKeyException e) {
			debug("Key not valid: " + e.getMessage());
			return null;
		} catch (InvalidAlgorithmParameterException e) {
			debug("Cipher Algorithm parameters not valid: " + e.getMessage());
			return null;
		}

		// Encrypt data

		byte[] encryptedText;
		try {
			encryptedText = cipher.doFinal(input);
		} catch (IllegalBlockSizeException e) {
			debug("Illegal block size: " + e.getMessage());
			return null;
		} catch (BadPaddingException e) {
			debug("Bad paggind exception: " + e.getMessage());
			return null;
		}
		return encryptedText;
	}

	public void onShowProvidersClick(View view) {
		Provider[] providers = Security.getProviders();
		for (Provider provider : providers) {
			debug("Provider: " + provider.getName());
			debug("Version : " + Double.toString(provider.getVersion()));
			debug("Info    : " + provider.getInfo());
			debug("N. Services : " + Integer.toString(provider.getServices().size()));
			debug("");
		}
	}

	public void onShowSCServicesClick(View view) {
		Provider spongyCastle = Security.getProvider("SC");
		if (spongyCastle == null) {
			debug("Spongy Castle Provider not available!");
			return;
		}

		debug("Spongy Castle Services:");
		for (Provider.Service service : spongyCastle.getServices())
			debug("- " + service.getAlgorithm());

	}

	private void debug(String message) {
		Log.v(TAG, message);
		outView.append(message + "\n");
	}

}
