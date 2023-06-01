package icesi.security;


public class Main {

    public static void main(String[] args) {

        try {
            menu();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void menu() throws Exception {

        System.out.println("1. Generar llave pública y privada.");
        System.out.println("2. Firmar documento.");
        System.out.println("3. Verificar firma del documento.");

        Security security = new Security();


    }
}