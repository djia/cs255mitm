package mitm;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;

/**
 * A utility class for handling passwords
 * 
 * The two main methods are:
 * (1) Given a plaintext password, generates a salt and puts the salt and the hash of the password + salt in a file.
 *     In the password file, the salt will be stored on the first line and the hash(password + salt) will be stored on the second line
 *     This will be done once to create our password file for the server
 * (2) Given a plaintext password, with check whether the password is the same as the one in the password file
 *  
 * @author djia
 *
 */
public class MITMAdminPasswordUtil {


	public static void main( String [] args ) {
		MITMAdminPasswordUtil passwordUtil = new MITMAdminPasswordUtil(args);
	}
	
	/**
	 * Takes arguments from the command line to generate the password file
	 * 
	 * @param args
	 */
	public MITMAdminPasswordUtil(String[] args) {
		String password = "";
		String pwdFile = "";
		try {
			for (int i=0; i<args.length; i++)
			{
				if (args[i].equals("-password")) {
					password = args[++i];
				} else if (args[i].equals("-pwdFile")) {
					pwdFile = args[++i];
				} else {
					throw printUsage();
				}
			}
		}
		catch (Exception e) {
			throw printUsage();
		}
		
		this.generatePasswordFile(password, pwdFile);
	}
	

	private Error printUsage() {
		System.err.println(
				"\n" +
						"Usage: " +
						"\n java " + MITMAdminPasswordUtil.class + " <options>" +
						"\n" +
						"\n Where options can include:" +
						"\n" +
						"\n   <-password <pass> >   " +
						"\n   <-pwdFile <pwdFile>" +
						"\n"
				);

		System.exit(1);
		return null;
	}
	
	/**
	 * Given a plaintext password, generates a salt and puts the salt and the hash of the password + salt in a file.
	 * In the password file, the salt will be stored on the first line and the hash(password + salt) will be stored on the second line
	 * 
	 * @param password the password to save in the password file
	 * @param pwdFile the file name for the password file
	 */
	private void generatePasswordFile(String password, String pwdFile) {
		// the password and the pwdFile has to be non-empty
		if(password.isEmpty()) {
			System.out.println("Please enter a non-empty password.");
			return;
		}
		if(pwdFile.isEmpty()) {
			System.out.println("Please enter a non-empty pwdFile.");
			return;
		}
		// generate a salt
		String salt = String.valueOf(UUID.randomUUID());
		
		try {
			String ciphertext = MITMAdminPasswordUtil.hashPassword(password, salt);
			
			// create the password file if it doesn't exist
			File file = new File(pwdFile);
			if(file.exists()) {
				// remove the file if it already exists
				file.delete();
			}
			file.createNewFile();
			
			// open the file for writing
			FileWriter fstream = new FileWriter(pwdFile, true);
		    BufferedWriter out = new BufferedWriter(fstream);
		    out.write(salt + "\n" + ciphertext);
		    out.close();
		    
		} catch (Exception e) {
			e.printStackTrace();
			return;
		}

		// successfully created the password file
		System.out.println("Successfully created the password file.");
	}
	
	
	/**
	 * given salt and password will calculate hash(password + salt)
	 * 
	 * @param salt
	 * @param password
	 * 
	 * @return hash(password + salt)
	 */
	public static String hashPassword(String password, String salt) {
		// create a message digest for SHA-256 and generate our hash value
		MessageDigest md;
		try {
			md = MessageDigest.getInstance("SHA-256");
			String plaintext = password + salt;
			
			md.update(plaintext.getBytes("UTF-8"));
			byte[] digest = md.digest();
			// convert the digest to a String ciphertext
			String ciphertext = MITMAdminPasswordUtil.bytesToString(digest);
			
		    return ciphertext;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
	
	
	/**
	 * Checks whether the password in the pwdFile is the same as the one given in this function
	 * 
	 * @param password
	 * @param pwdFile
	 * 
	 * @return true if and only if passwords match
	 */
	public static boolean checkPassword(String password, String pwdFile) {
		
		// open the file and retrieve the password and salt
		String content = MITMAdminPasswordUtil.readFile(pwdFile);
		if(content.isEmpty()) {
			System.out.println("The password file is invalid. Please try again.");
			return false;
		}
		
		// get the salt from the first line and the password from the second line
		String[] tokens = content.split("\n");
		// make sure the content string is valid
		if(tokens.length < 2) {
			System.out.println("The password file is invalid. Please try again.");
			return false;
		}
		String salt = tokens[0];
		String ciphertext = tokens[1];
		
		// get the ciphertext for the password given in the input and the salt we got from the file
		String checkCiphertext = MITMAdminPasswordUtil.hashPassword(password, salt);
		
		// see if the two ciphertext are equal
		return ciphertext.equals(checkCiphertext);
	}
	
	
	/**
	 * read from a file, and return the contents
	 */
	public static String readFile(String fileName) {
		if(fileName == null) {
			return "";
		}
		String content = "";
		// make sure file exists
		File file = new File(fileName);
		if(!file.exists()) {
			System.out.println("The file was not found. Please try again.");
			return content;
		}
		
		try {
			FileInputStream fstream = new FileInputStream(fileName);
			FileChannel fc = fstream.getChannel();
		    MappedByteBuffer bb = fc.map(FileChannel.MapMode.READ_ONLY, 0, fc.size());
		    /* Instead of using default, pass in a decoder. */
		    content = Charset.defaultCharset().decode(bb).toString();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return content;
	}
	
	
	/**
	 * write to a file, will remove the file if it already exists
	 */
	public static void writeFile(String fileName, String content) {
		// create the password file if it doesn't exist
		File file = new File(fileName);
		if(file.exists()) {
			// remove the file if it already exists
			file.delete();
		}
		try {
			file.createNewFile();
			// open the file for writing
			FileWriter fstream = new FileWriter(fileName, true);
		    BufferedWriter out = new BufferedWriter(fstream);
		    out.write(content);
		    out.close();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	
	
	/**
	 * Given a byte[] array, produces a hex String,
	 * such as "234a6f". with 2 chars for each byte in the array.
	*/
	public static String bytesToString(byte[] bytes) {
		StringBuffer buff = new StringBuffer();
		for (int i=0; i<bytes.length; i++) {
			int val = bytes[i];
			val = val & 0xff;  // remove higher bits, sign
			if (val<16) buff.append('0'); // leading 0
			buff.append(Integer.toString(val, 16));
		}
		return buff.toString();
	}
	
	/**
	 * Given a string of hex byte values such as "24a26f", creates
	 * a byte[] array of those values, one byte value -128..127
	 * for each 2 chars.
	*/
	public static byte[] stringToBytes(String hex) {
		byte[] result = new byte[hex.length()/2];
		for (int i=0; i<hex.length(); i+=2) {
			result[i/2] = (byte) Integer.parseInt(hex.substring(i, i+2), 16);
		}
		return result;
	}
	
	
	
}
