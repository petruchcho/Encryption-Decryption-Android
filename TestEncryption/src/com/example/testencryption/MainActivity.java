package com.example.testencryption;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Calendar;
import java.util.GregorianCalendar;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.security.auth.x500.X500Principal;

import android.content.Context;
import android.os.Bundle;
import android.security.KeyPairGeneratorSpec;
import android.support.v7.app.ActionBarActivity;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

public class MainActivity extends ActionBarActivity {

	EditText dataField, encryptedField, decryptedField;
	Button eButton, dButton;

	final static String fileName = "storage";
	final static String alias = "key_alias";

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);

		dataField = (EditText) findViewById(R.id.data_field);
		encryptedField = (EditText) findViewById(R.id.encrypted_field);
		decryptedField = (EditText) findViewById(R.id.decrypted_field);

		eButton = (Button) findViewById(R.id.e_button);
		dButton = (Button) findViewById(R.id.d_button);

		eButton.setOnClickListener(new OnClickListener() {

			@Override
			public void onClick(View v) {
				String data = dataField.getText().toString();
				try {
					generateNewKey(alias);
					encryptData((RSAPublicKey) getKey().getCertificate()
							.getPublicKey(), data);
				} catch (Exception e1) {
					e1.printStackTrace();
					Toast.makeText(getApplicationContext(), e1.getMessage(),
							Toast.LENGTH_LONG).show();
				}
			}
		});

		dButton.setOnClickListener(new OnClickListener() {

			@Override
			public void onClick(View v) {
				try {
					String decryptedData = getDecryptedData((RSAPrivateKey) getKey()
							.getPrivateKey());
					decryptedField.setText(decryptedData);
				} catch (IOException | InvalidKeyException
						| IllegalBlockSizeException | BadPaddingException
						| NoSuchAlgorithmException | NoSuchPaddingException
						| UnrecoverableEntryException | KeyStoreException
						| CertificateException | NoSuchProviderException e) {
					e.printStackTrace();
					Toast.makeText(getApplicationContext(), e.getMessage(),
							Toast.LENGTH_LONG).show();
				}
			}
		});
	}

	void encryptData(RSAPublicKey key, String data) throws InvalidKeyException,
			NoSuchAlgorithmException, NoSuchProviderException,
			NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException, UnsupportedEncodingException, IOException {
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding",
				"AndroidOpenSSL");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		writeToFileWithCipherStream(cipher, data);
	}

	String getDecryptedData(RSAPrivateKey key) throws InvalidKeyException,
			NoSuchAlgorithmException, NoSuchProviderException,
			NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException, IOException {
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding",
				"AndroidOpenSSL");
		cipher.init(Cipher.DECRYPT_MODE, key);
		CipherInputStream cipherInputStream = new CipherInputStream(
				new FileInputStream(getFilePath()), cipher);
		byte[] roundTrippedBytes = new byte[1000]; // TODO: dynamically resize
													// as we get more data

		int index = 0;
		int nextByte;
		while ((nextByte = cipherInputStream.read()) != -1) {
			roundTrippedBytes[index] = (byte) nextByte;
			index++;
		}
		cipherInputStream.close();
		return new String(roundTrippedBytes, 0, index, "UTF-8");
	}

	void writeToFileWithCipherStream(Cipher cipher, String data)
			throws UnsupportedEncodingException, IOException {
		CipherOutputStream cipherOutputStream = new CipherOutputStream(
				new FileOutputStream(getFilePath()), cipher);
		cipherOutputStream.write(data.getBytes("UTF-8"));
		cipherOutputStream.close();
	}

	String getFilePath() {
		String filesDirectory = getFilesDir().getAbsolutePath();
		String encryptedDataFilePath = filesDirectory + File.separator
				+ fileName;
		return encryptedDataFilePath;
	}

	void generateNewKey(String alias) throws NoSuchAlgorithmException,
			NoSuchProviderException, InvalidAlgorithmParameterException,
			KeyStoreException, CertificateException, IOException {
		KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
		keyStore.load(null);
		if (!keyStore.containsAlias(alias)) {
			Calendar start = new GregorianCalendar();
			Calendar end = new GregorianCalendar();
			end.add(1, Calendar.YEAR);

			KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(this)
					.setAlias(alias)
					.setSubject(new X500Principal("CN=" + alias))
					.setSerialNumber(BigInteger.valueOf(1337))
					.setStartDate(start.getTime()).setEndDate(end.getTime())
					.build();
			KeyPairGenerator kpGenerator = KeyPairGenerator.getInstance("RSA",
					"AndroidKeyStore");
			kpGenerator.initialize(spec);
			kpGenerator.generateKeyPair();
		}
	}
	
	KeyStore.PrivateKeyEntry getKey() throws KeyStoreException,
			NoSuchAlgorithmException, CertificateException, IOException,
			UnrecoverableEntryException {
		KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
		keyStore.load(null);
		return (PrivateKeyEntry) keyStore.getEntry(alias, null);
	}
}
