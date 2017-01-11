import com.goffity.demo.encryption.RSAEncryption;

class Main {
    public static void main(String[] args) throws Exception {
        RSAEncryption rsaEncryption = new RSAEncryption();

        rsaEncryption.init();

        if (!rsaEncryption.isKeyExists()) {
            rsaEncryption.generateKey();
        }

        String encrypted = rsaEncryption.encrypt("abcdefghijklmnopqrstuvwxyz | ABCDEFGHIJKLMNOPQRSTUVWXYZ | กขฃคฅฆงจฉชซฌญฎฏฐฑฒณดตถทธนบปผฝพฟภมยรลวศษสหฬอฮ | 1234567890!@#$%^&*()_+|}{\\");
        System.out.println("encrypted: " + encrypted);

        StringBuilder stringBuilder = new StringBuilder("");

        for (int i = 0; i < encrypted.length(); i++) {
            stringBuilder.append("-");
        }

        System.out.println(stringBuilder.toString());

        String decrypted = rsaEncryption.decrypt(encrypted);
        System.out.println("decrypted:" + decrypted);
    }
}
