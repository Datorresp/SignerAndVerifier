package icesi.security;


import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.NoSuchElementException;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) {

        try {
            menu();
        } catch (Exception e) {
           
        }
    }

    public static void menu() throws Exception {

        System.out.println("1. Generar llave pública y privada.");
        System.out.println("2. Firmar documento.");
        System.out.println("3. Verificar firma del documento.");
        System.out.println("4. Salir.");

        Security security = new Security();

        Scanner num = new Scanner(System.in);
        Scanner filess = new Scanner(System.in);
        boolean quit = false;
        
        
		while(!quit) {
			int answer = num.nextInt();
			
			try {
			switch (answer) {

			case 1:

				char[] password;
				System.out.println("Digite la contraseña para la llave privada (16 caracteres)");
				password = filess.nextLine().toCharArray();
				security.keyGenerator(password);
				System.out.println("La llave ha sido generada.");
				menu();
				break;
			case 2:

				System.out.println("Digite el nombre del archivo de la clave privada. *.cif)");
				String privateKeyPath = filess.nextLine();

				File inputFile = new File(privateKeyPath);
				System.out.print("Digite la contraseña para desencriptar la clave privada");
				char[] password2 = filess.nextLine().toCharArray();

				try {
					byte[] output = security.passwordCheck(security.getKeyFromPassword(password2), inputFile);

					if (output != null) {

						System.out.println("Llave privada desencriptada.");

						PrivateKey pk = security.convertKeyToPrivate(output);

						System.out.print("Digite el nombre del archivo para firmar.");
						String fileToSign = filess.nextLine();

						if (new File(fileToSign).exists()) {

							security.signFile(fileToSign, pk);
							System.out.println("Archivo firmado.");
						} else {

							System.out.println("Archivo '" + fileToSign + "' NO existe.");
						}
					} else {

						menu();
					}
				} catch (InvalidKeyException | NoSuchPaddingException | NoSuchAlgorithmException
						| InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException
						| InvalidKeySpecException | IOException e) {

					e.printStackTrace();
				}
				menu();
				break;
			case 3:
				System.out.println("Digite el nombre del archivo que desea revisar.");
				String fileToCheck = filess.nextLine();

				System.out.println("Digite el nombre completo del archivo con la firma.");
				String sign = filess.nextLine();

				System.out.println("Digite el nombre completo del archivo con la clave pública.");
				String publicKeyPath = filess.nextLine();

				File publicKey = new File(publicKeyPath);

				if (publicKey.exists()) {

					try {
						if (security.verifySign(fileToCheck, sign, publicKey)) {

							System.out.println("SI ES LA FIRMA!");
							
						} else {

							System.out.println("La firma no coincide");
						}
					} catch (IOException e) {

						e.printStackTrace();
					}
				} else {

					System.out.println("El archivo de clave publica no existe");
				}
				menu();
				break;

			case 4:
				System.out.println("Gracias por usar nuestro codigo.");
				quit = true;
				filess.close();
				num.close();
				break;

			default:

				System.out.println("Seleccione una de las opciones especificadas.");
				break;
			}
			}catch(NoSuchElementException e) {
				System.out.println("Chao c:");
			}

		}

	}
}