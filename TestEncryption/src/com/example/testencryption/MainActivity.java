package com.example.testencryption;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
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

import android.os.Bundle;
import android.security.KeyPairGeneratorSpec;
import android.support.v7.app.ActionBarActivity;
import android.util.Base64;
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
					// encryptData((RSAPublicKey) getKey().getCertificate()
					// .getPublicKey(), data);
					Cipher cipher = Cipher.getInstance("RSA/NONE/NoPadding");
					cipher.init(Cipher.ENCRYPT_MODE, (RSAPublicKey) getKey()
							.getCertificate().getPublicKey());
					String encryptedString = encrypt(data, cipher);
					encryptedField.setText(encryptedString);
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
					// String decryptedData = getDecryptedData((RSAPrivateKey)
					// getKey()
					// .getPrivateKey());
					Cipher cipher = Cipher.getInstance("RSA/NONE/NoPadding");
					cipher.init(Cipher.DECRYPT_MODE, (RSAPrivateKey) getKey()
							.getPrivateKey());
					String decryptedString = decrypt(encryptedField.getText()
							.toString(), cipher);
					decryptedField.setText(decryptedString);
					// decryptedField.setText(decryptedData);
				} catch (Exception e) {
					e.printStackTrace();
					Toast.makeText(getApplicationContext(), e.getMessage(),
							Toast.LENGTH_LONG).show();
				}
			}
		});
	}

	public String encrypt(String plaintext, Cipher cipher) throws Exception {
		byte[] bytes = plaintext.getBytes("UTF-8");

		byte[] encrypted = blockCipher(bytes, Cipher.ENCRYPT_MODE, cipher);

		String encryptedTranspherable = Base64.encodeToString(encrypted,
				Base64.DEFAULT);
		return encryptedTranspherable;
	}

	public String decrypt(String encrypted, Cipher cipher) throws Exception {
		byte[] bts = Base64.decode(encrypted, Base64.DEFAULT);

		byte[] decrypted = blockCipher(bts, Cipher.DECRYPT_MODE, cipher);

		return new String(decrypted, "UTF-8");
	}

	private byte[] blockCipher(byte[] bytes, int mode, Cipher cipher)
			throws IllegalBlockSizeException, BadPaddingException {
		// string initialize 2 buffers.
		// scrambled will hold intermediate results
		byte[] scrambled = new byte[0];

		// toReturn will hold the total result
		byte[] toReturn = new byte[0];
		// if we encrypt we use 100 byte long blocks. Decryption requires 128
		// byte long blocks (because of RSA)
		int length = (mode == Cipher.ENCRYPT_MODE) ? 100 : 128;

		// another buffer. this one will hold the bytes that have to be modified
		// in this step
		byte[] buffer = new byte[length];

		for (int i = 0; i < bytes.length; i++) {

			// if we filled our buffer array we have our block ready for de- or
			// encryption
			if ((i > 0) && (i % length == 0)) {
				// execute the operation
				scrambled = cipher.doFinal(buffer);
				// add the result to our total result.
				toReturn = append(toReturn, scrambled);
				// here we calculate the length of the next buffer required
				int newlength = length;

				// if newlength would be longer than remaining bytes in the
				// bytes array we shorten it.
				if (i + length > bytes.length) {
					newlength = bytes.length - i;
				}
				// clean the buffer array
				buffer = new byte[newlength];
			}
			// copy byte into our buffer.
			buffer[i % length] = bytes[i];
		}

		// this step is needed if we had a trailing buffer. should only happen
		// when encrypting.
		// example: we encrypt 110 bytes. 100 bytes per run means we "forgot"
		// the last 10 bytes. they are in the buffer array
		scrambled = cipher.doFinal(buffer);

		// final step before we can return the modified data.
		toReturn = append(toReturn, scrambled);

		return toReturn;
	}

	private byte[] append(byte[] prefix, byte[] suffix) {
		byte[] toReturn = new byte[prefix.length + suffix.length];
		for (int i = 0; i < prefix.length; i++) {
			toReturn[i] = prefix[i];
		}
		for (int i = 0; i < suffix.length; i++) {
			toReturn[i + prefix.length] = suffix[i];
		}
		return toReturn;
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
		//if (!keyStore.containsAlias(alias)) {
			Calendar start = new GregorianCalendar();
			Calendar end = new GregorianCalendar();
			end.add(1, Calendar.YEAR);

			KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(this)
					.setAlias(alias)
					.setSubject(new X500Principal("CN=" + alias))
					.setSerialNumber(BigInteger.valueOf(1337)).setKeySize(1024)
					.setStartDate(start.getTime()).setEndDate(end.getTime())
					.build();
			KeyPairGenerator kpGenerator = KeyPairGenerator.getInstance("RSA",
					"AndroidKeyStore");
			kpGenerator.initialize(spec);
			kpGenerator.generateKeyPair();
	//	}
	}

	KeyStore.PrivateKeyEntry getKey() throws KeyStoreException,
			NoSuchAlgorithmException, CertificateException, IOException,
			UnrecoverableEntryException {
		KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
		keyStore.load(null);
		return (PrivateKeyEntry) keyStore.getEntry(alias, null);
	}
}
