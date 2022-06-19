package lab6CalculadoraHash;

import java.awt.BorderLayout;
import java.awt.EventQueue;

import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.SwingConstants;
import java.awt.Color;
import java.awt.Font;
import javax.swing.JTextField;
import javax.swing.JComboBox;
import javax.swing.JTextArea;
import javax.swing.JScrollBar;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import java.awt.event.ActionListener;
import java.io.UnsupportedEncodingException;
import java.awt.event.ActionEvent;

//Librerias para algoritmos
import java.security.NoSuchAlgorithmException;  
import java.math.BigInteger;  
import java.security.MessageDigest;  
import java.nio.charset.StandardCharsets;  

import java.security.*;  
import java.math.BigInteger;  
import java.security.MessageDigest;  
import java.nio.charset.StandardCharsets;  
import javax.crypto.spec.PBEKeySpec;   
import javax.crypto.SecretKeyFactory;  
import java.security.spec.InvalidKeySpecException;  

import java.security.NoSuchProviderException;  
import java.security.MessageDigest;  
import java.security.SecureRandom; 
import java.security.Security;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;

import org.apache.commons.codec.binary.Hex;

//Hecho por: Jimy Revilla
//Curso: Laboratorio de Seguridad Informatica

public class CalculadoraHash extends JFrame {

	private JPanel contentPane;
	private JTextField txtTextoClaro;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					CalculadoraHash frame = new CalculadoraHash();
					frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Create the frame.
	 */
	public CalculadoraHash() {
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(100, 100, 548, 386);
		contentPane = new JPanel();
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		setContentPane(contentPane);
		contentPane.setLayout(null);
		
		JLabel lblNewLabel = new JLabel("Calculadora Hash");
		lblNewLabel.setVerticalAlignment(SwingConstants.BOTTOM);
		lblNewLabel.setForeground(Color.WHITE);
		lblNewLabel.setFont(new Font("Yu Gothic Medium", Font.PLAIN, 50));
		lblNewLabel.setBackground(new Color(51, 153, 153));
		lblNewLabel.setOpaque(true);
		lblNewLabel.setHorizontalAlignment(SwingConstants.CENTER);
		lblNewLabel.setBounds(0, 0, 532, 94);
		contentPane.add(lblNewLabel);
		
		JLabel lblNewLabel_1 = new JLabel("Hecho por: Jimy Revilla");
		lblNewLabel_1.setFont(new Font("Tempus Sans ITC", Font.PLAIN, 11));
		lblNewLabel_1.setForeground(Color.BLACK);
		lblNewLabel_1.setBounds(409, 325, 123, 22);
		contentPane.add(lblNewLabel_1);
		
		txtTextoClaro = new JTextField();
		txtTextoClaro.setBounds(10, 130, 356, 20);
		contentPane.add(txtTextoClaro);
		txtTextoClaro.setColumns(10);
		
		JLabel lblNewLabel_2 = new JLabel("Inserte el mensaje en claro y el modo de cifrado");
		lblNewLabel_2.setBounds(10, 105, 262, 14);
		contentPane.add(lblNewLabel_2);
		
		JComboBox cmbModo = new JComboBox();
		cmbModo.setModel(new DefaultComboBoxModel(new String[] {"Ninguno", "MD4", "MD5", "SHA1", "SHA256", "HMAC"}));
		cmbModo.setBounds(369, 129, 71, 22);
		contentPane.add(cmbModo);
		
		JLabel lblNewLabel_3 = new JLabel("Salida");
		lblNewLabel_3.setBounds(10, 161, 46, 14);
		contentPane.add(lblNewLabel_3);
		
		JTextArea txtSalida = new JTextArea();
		txtSalida.setEditable(false);
		txtSalida.setLineWrap (true);
		txtSalida.setWrapStyleWord(true);
		txtSalida.setBounds(10, 186, 512, 133);
		contentPane.add(txtSalida);
		
		JButton btnInicio = new JButton("Iniciar");
		btnInicio.setBackground(new Color(0, 204, 255));
		btnInicio.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if(cmbModo.getSelectedIndex()==0) { //Selecciono "Ninguno"
					JOptionPane.showMessageDialog(btnInicio, "Debe seleccionar una opcion");
				}else if(cmbModo.getSelectedIndex()==1) { //MD4
					String msg= txtTextoClaro.getText();
					String result = null;
			        try {
			            MessageDigest md = MessageDigest.getInstance("MD4");
			            byte[] mdBytes = md.digest(msg.getBytes());
			            // toHex
			            result = Hex.encodeHexString(mdBytes);
			        } catch (NoSuchAlgorithmException error) {
			            // e.printStackTrace();
			            result = error.getMessage();
			        }
			        System.out.println("MD4:"+result);
			        txtSalida.setText(result);
			    
				}else if(cmbModo.getSelectedIndex()==2) { //MD5
					String str = txtTextoClaro.getText(); 
					String hash = getMd5(str);    
					System.out.println("The HashCode Generated for " + str + " is: " + hash);  
					txtSalida.setText(hash);
				}else if(cmbModo.getSelectedIndex()==3){ //SHA1
			        String  orgPassword = txtTextoClaro.getText(); 
			          
			        String createdSecuredPasswordHash="";
					try {
						createdSecuredPasswordHash = createStrongPasswordHash(orgPassword);
					} catch (NoSuchAlgorithmException | InvalidKeySpecException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}  
			        System.out.println(createdSecuredPasswordHash);
			        txtSalida.setText(createdSecuredPasswordHash);
			        
				}else if(cmbModo.getSelectedIndex()==4) { //SHA256
					try {    
						String str = txtTextoClaro.getText();  
						String hash = toHexStr(obtainSHA(str));  
						System.out.println("\n" + str + " : " + hash);
						txtSalida.setText(hash);
						  
					}  
					catch (NoSuchAlgorithmException obj){  
						System.out.println("An exception is generated for the incorrect algorithm: " + obj);  
					}  
				}else if(cmbModo.getSelectedIndex()==5) { //HMAC
					 try {
					      byte[] hmacSha256 = calcHmacSha256("secret123".getBytes("UTF-8"), txtTextoClaro.getText().getBytes("UTF-8"));
					      System.out.println(String.format("Hex: %064x", new BigInteger(1, hmacSha256)));
					      txtSalida.setText(String.format("Hex: %064x", new BigInteger(1, hmacSha256)));
					    } catch (UnsupportedEncodingException error) {
					      error.printStackTrace();
					    }
				}
			}
			
			
			//Metodos MD5
			private  String getMd5(String input) {  
				try{   
					MessageDigest msgDst = MessageDigest.getInstance("MD5");  
					byte[] msgArr = msgDst.digest(input.getBytes());  
					BigInteger bi = new BigInteger(1, msgArr);  
					String hshtxt = bi.toString(16);  
					while (hshtxt.length() < 32) {  
						hshtxt = "0" + hshtxt;  
					}  
					return hshtxt;  
					}  
					// for handling the exception   
				catch (NoSuchAlgorithmException abc){  
					throw new RuntimeException(abc);  
				}  
			}  
			
			//Metodos SHA1
			 private  String createStrongPasswordHash(String password) throws NoSuchAlgorithmException, InvalidKeySpecException {   
			        int itr = 500;  
			        char[] charArr = password.toCharArray();  
			        byte[] saltArr = obtainSalt();  
			           
			        PBEKeySpec pbeSpec = new PBEKeySpec(charArr, saltArr, itr, 64 * 8);  
			          
			        // using PBKDF2WithHmacSHA1 for hashing  
			        SecretKeyFactory secKeyFact = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");  
			        byte[] hashArr = secKeyFact.generateSecret(pbeSpec).getEncoded();  
			        return intoHex(hashArr);  
			 }  
			         
			    private  byte[] obtainSalt() throws NoSuchAlgorithmException  
			    {  
			        SecureRandom secRand = SecureRandom.getInstance("SHA1PRNG");  
			        byte[] saltArr = new byte[16];  
			        secRand.nextBytes(saltArr);  
			        return saltArr;  
			    }  
			       
			       
			    private  String intoHex(byte[] arr) throws NoSuchAlgorithmException  
			    {  
			        BigInteger bInt = new BigInteger(1, arr);  
			        String hexStr = bInt.toString(16);  
			        int paddingLen = (arr.length * 2) - hexStr.length();  
			        if(paddingLen > 0)  
			        {  
			            return String.format("%0"  + paddingLen + "d", 0) + hexStr;  
			        }  
			        else  
			        {  
			            return hexStr;  
			        } 
			    }			
			//Metodos SHA256
			private byte[] obtainSHA(String s) throws NoSuchAlgorithmException{
				MessageDigest msgDgst = MessageDigest.getInstance("SHA-256");  
				return msgDgst.digest(s.getBytes(StandardCharsets.UTF_8)); 
			}
			private static String toHexStr(byte[] hash)  {  
				BigInteger no = new BigInteger(1, hash);   
				StringBuilder hexStr = new StringBuilder(no.toString(16));  
				  
				while (hexStr.length() < 32)  {  
					hexStr.insert(0, '0');  
				}return hexStr.toString();  
			}  
			//Metodos HMAC
			static public byte[] calcHmacSha256(byte[] secretKey, byte[] message) {
			    byte[] hmacSha256 = null;
			    try {
				    Mac mac = Mac.getInstance("HmacSHA256");
				    SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey, "HmacSHA256");
				    mac.init(secretKeySpec);
				    hmacSha256 = mac.doFinal(message);
			    } catch (Exception e) {
			    	throw new RuntimeException("Failed to calculate hmac-sha256", e);
			    }
			    return hmacSha256;
			  }
	});
		btnInicio.setBounds(443, 129, 79, 23);
		contentPane.add(btnInicio);
		
	}
}


