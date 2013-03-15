/**
 * CS255 project 2
 */
package mitm;

import java.io.*;
import java.net.*;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;

/**
 * Performs a Challenge-Response type authentication with the MITMAdminCRServer
 * Uses a keystore that gives our private keys so we can sign messages and
 * perform CR authentication.
 * 
 * Will also take in a command that will be performed by the server if the CR is successful
 * 
 * @author djia
 *
 */
public class MITMAdminCRClient
{
	private Socket m_remoteSocket;
	private String keyStore = "";
	private char[] keyStorePassword = null;
	private String alias = "";
	private String command;
	private String commonName = "";
	private int remotePort;
	private String remoteHost;

	public static void main( String [] args ) {
		MITMAdminCRClient admin = new MITMAdminCRClient( args );
		admin.run();
	}

	private Error printUsage() {
		System.err.println(
				"\n" +
						"Usage: " +
						"\n java " + MITMAdminCRClient.class + " <options>" +
						"\n" +
						"\n Where options can include:" +
						"\n" +
						"\n   <-keyStore <ks> >   " +
						"\n   <-keyStorePassword <pass> >" +
						"\n   <-keyStoreAlias <alias> >" +
						"\n   <-cmd <shudown|stats>" +
						"\n   [-remoteHost <host name/ip>]  Default is localhost" +
						"\n   [-remotePort <port>]          Default is 8002" +
						"\n"
				);

		System.exit(1);
		return null;
	}


	private static class TrustEveryone implements javax.net.ssl.X509TrustManager
	{
		public void checkClientTrusted(java.security.cert.X509Certificate[] chain,
				String authenticationType) {
		}

		public void checkServerTrusted(java.security.cert.X509Certificate[] chain,
				String authenticationType) {
		}

		public java.security.cert.X509Certificate[] getAcceptedIssuers()
		{
			return null;
		}
	}


	private MITMAdminCRClient( String [] args ) {
		remotePort = 8002;
		remoteHost = "localhost";

		if( args.length < 4 )
			throw printUsage();

		try {
			for (int i=0; i<args.length; i++)
			{
				if (args[i].equals("-remoteHost")) {
					remoteHost = args[++i];
				} else if (args[i].equals("-remotePort")) {
					remotePort = Integer.parseInt(args[++i]);
				} else if (args[i].equals("-cmd")) {
					command = args[++i];
					if( command.equals("enable") || command.equals("disable") ) {
						commonName = args[++i];
					}
				} else if (args[i].equals("-keyStore")) {
					keyStore = args[++i];
				} else if (args[i].equals("-keyStorePassword")) {
					keyStorePassword = args[++i].toCharArray();
				} else if (args[i].equals("-keyStoreAlias")) {
					alias = args[++i];
				} else {
					throw printUsage();
				}
			}
			
		}
		catch (Exception e) {
			throw printUsage();
		}

	}

	public void run() 
	{
		try {
			SSLContext sslContext = SSLContext.getInstance( "SSL" );
			sslContext.init(new javax.net.ssl.KeyManager[] {} , new TrustManager[] { new TrustEveryone() } , null);
			m_remoteSocket = (SSLSocket) sslContext.getSocketFactory().createSocket( remoteHost, remotePort );
			
			if( m_remoteSocket != null ) {
				
				PrintWriter writer = new PrintWriter( m_remoteSocket.getOutputStream() );
				writer.print("initCR");
				writer.flush();
				
				System.out.println("");
				System.out.println("Receiving input from MITM proxy:");
				System.out.println("");
				BufferedReader r = new BufferedReader(new InputStreamReader(m_remoteSocket.getInputStream()));
				String line = null;
				String message = null;
				while ((line = r.readLine()) != null) {
//					System.out.println(line);
					message = line;
//					break;
				}
//				System.out.println(message);
				
//				System.err.println("Admin Client exited");
//				System.exit(0);
				

				// sign the message with the cmd and send it back along with the cmd as plaintext
				// get the signature
				String signature = MITMAdminKSUtil.getSignature(keyStore, keyStorePassword, alias, message + command);
				System.out.println(signature);
				
				
				sslContext = SSLContext.getInstance( "SSL" );
				sslContext.init(new javax.net.ssl.KeyManager[] {} , new TrustManager[] { new TrustEveryone() } , null);
				m_remoteSocket = (SSLSocket) sslContext.getSocketFactory().createSocket( remoteHost, remotePort );
				
				
				// send it back
				writer = new PrintWriter( m_remoteSocket.getOutputStream() );
				writer.println("signature:"+signature);
				writer.println("command:"+command);
				writer.flush();
				
				// now read back any response

				System.out.println("");
				System.out.println("Receiving input from MITM proxy:");
				System.out.println("");
				
				r = new BufferedReader(new InputStreamReader(m_remoteSocket.getInputStream()));
				while ((line = r.readLine()) != null) {
					System.out.println(line);
				}
				
				System.err.println("Admin Client exited");
				System.exit(0);
			}
			
			
		} catch (Exception e) {
			e.printStackTrace();
		}
		System.err.println("Admin Client exited");
		System.exit(0);
	}
}
