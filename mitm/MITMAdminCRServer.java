/**
 * CS255 project 2
 */

package mitm;

import java.net.*;
import java.io.*;
import java.security.GeneralSecurityException;
import java.util.*;
import java.util.regex.*;
import mitm.MITMAdminPasswordUtil;

class MITMAdminCRServer implements Runnable
{
	private ServerSocket m_serverSocket;
	private Socket m_socket = null;
	private HTTPSProxyEngine m_engine;
	private String pkFile = null;
	private String message;

	public MITMAdminCRServer( String localHost, int adminPort, HTTPSProxyEngine engine, String pkFile ) throws IOException,GeneralSecurityException {
		MITMSSLSocketFactory socketFactory = new MITMSSLSocketFactory();

		m_serverSocket = socketFactory.createServerSocket( localHost, adminPort, 0 );
		m_engine = engine;
		
		// save the pkFile (file name of the public key file) so we can verify signatures later
		this.pkFile = pkFile;
	}

	public void run() {
		System.out.println("Admin server initialized, listening on port " + m_serverSocket.getLocalPort());
		while( true ) {
			try {
				m_socket = m_serverSocket.accept();

				byte[] buffer = new byte[40960];

				BufferedInputStream in = new BufferedInputStream(m_socket.getInputStream(), buffer.length);
				
				// Read a buffer full.
				int bytesRead = in.read(buffer);
				
				String line = bytesRead > 0 ? new String(buffer, 0, bytesRead) : "";
				// if there's nothing t
				if(line.isEmpty()) {
					continue;
				}
				System.out.println(line);
				
//				this.sendString("I got yo message!");
				
				
				// see what stage of the Challenger Response we are currently at
				if(line.equals("initCR")) {
					// initializing the CR
					this.message = String.valueOf(UUID.randomUUID());
					// send this message to the client for signature
					this.sendString(message);
					// wait for signature to be sent back
					m_socket.close();
				} else {
					// verifying the signature and send response to command if verified
					
					// get pattern to parse the input
					Pattern userPwdPattern = Pattern.compile("signature:(\\S+)\\s+command:(\\S+)\\s");
					Matcher userPwdMatcher = userPwdPattern.matcher(line);
					
					// parse username and pwd
					if (userPwdMatcher.find()) {
						String signature = userPwdMatcher.group(1);
						String command = userPwdMatcher.group(2);
						
						// TODO(cs255): authenticate the user
						boolean authenticated = MITMAdminKSUtil.verifySignature(this.pkFile, signature, message + command);
						
						// make sure to reset the message after each check, so message is never used more than once
						this.message = "";
						
						// if authenticated, do the command
						if( authenticated ) {
							doCommand( command );
						} else {
							// tell the client that authentication failed
							sendString("Sorry, the authentication failed.");
							m_socket.close();
						}
					}
				}
				
			}
			catch( InterruptedIOException e ) {
			}
			catch( Exception e ) {
				e.printStackTrace();
			}
		}
	}

	private void sendString(final String str) throws IOException {
		PrintWriter writer = new PrintWriter( m_socket.getOutputStream() );
		writer.println(str);
		writer.flush();
	}

	private void doCommand( String cmd ) throws IOException {

		// TODO(cs255): instead of greeting admin client, run the indicated command
		
		/**
		 * depending on the cmd the user has chosen, we will perform the action on the HTTPSProxyEngine
		 */
		if(cmd.equalsIgnoreCase("stats")) {
			sendString("Total number of connections so far: " + Integer.toString(this.m_engine.getNumConnects()));
		} else if(cmd.equalsIgnoreCase("shutdown")) {
			sendString("The server has been successfully shutdown.");
			System.exit(0);
		} else {
			sendString("Please enter a valid command <shudown|stats>");
		}

		// sendString("How are you Admin Client !!");

		m_socket.close();

	}

}
