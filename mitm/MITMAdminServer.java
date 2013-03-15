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

class MITMAdminServer implements Runnable
{
	private ServerSocket m_serverSocket;
	private Socket m_socket = null;
	private HTTPSProxyEngine m_engine;
	private String pwdFile = null;

	public MITMAdminServer( String localHost, int adminPort, HTTPSProxyEngine engine, String pwdFile ) throws IOException,GeneralSecurityException {
		MITMSSLSocketFactory socketFactory = new MITMSSLSocketFactory();

		m_serverSocket = socketFactory.createServerSocket( localHost, adminPort, 0 );
		m_engine = engine;
		
		// save the pwdFile (file name of the password file) so we can compare passwords later
		this.pwdFile = pwdFile;
	}

	public void run() {
		System.out.println("Admin server initialized, listening on port " + m_serverSocket.getLocalPort());
		while( true ) {
			try {
				m_socket = m_serverSocket.accept();

				byte[] buffer = new byte[40960];

				Pattern userPwdPattern = Pattern.compile("password:(\\S+)\\s+command:(\\S+)\\sCN:(\\S*)\\s");

				BufferedInputStream in = new BufferedInputStream(m_socket.getInputStream(), buffer.length);

				// Read a buffer full.
				int bytesRead = in.read(buffer);

				String line = bytesRead > 0 ? new String(buffer, 0, bytesRead) : "";
	
				Matcher userPwdMatcher = userPwdPattern.matcher(line);
				
				// parse username and pwd
				if (userPwdMatcher.find()) {
					String password = userPwdMatcher.group(1);
					
					// TODO(cs255): authenticate the user
					boolean authenticated = MITMAdminPasswordUtil.checkPassword(password, this.pwdFile);
	
					// if authenticated, do the command
					if( authenticated ) {
						String command = userPwdMatcher.group(2);
						String commonName = userPwdMatcher.group(3);
	
						doCommand( command );
					} else {
						// tell the client that authentication failed
						sendString("Sorry, the authentication failed.");
						m_socket.close();
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
