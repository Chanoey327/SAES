import java.util.List;

public class TestSAES {
    private static String toBin16(int value) {
        return String.format("%16s", Integer.toBinaryString(value & 0xFFFF)).replace(' ', '0');
    }

    public static void main(String[] args) {
        /*
         * 基本加密测试，给出16bit明文和16bit密钥，输出16bit密文
         */
        int plaintext = 0b1001110111011010;
        int key = 0b1001001110110101;
        int ciphertext = SAES.encrypt(plaintext, key);
        int decrypttext = SAES.decrypt(ciphertext, key);
        System.out.printf("Basic Test\n");
        System.out.printf("Plaintext:  %16s\n", Integer.toBinaryString(plaintext).replace(' ', '0'));
        System.out.printf("Key:        %16s\n", Integer.toBinaryString(key).replace(' ', '0'));
        System.out.printf("Round Keys:  K1=%16s K2=%16s\n",
                toBin16(SAES.getRoundKey1(key)),
                toBin16(SAES.getRoundKey2(key)));
        System.out.printf("Ciphertext: %s\n", toBin16(ciphertext));
        System.out.printf("Decrypted:  %16s\n\n", Integer.toBinaryString(decrypttext).replace(' ', '0'));
        if (decrypttext==plaintext) {
            System.out.println("Basic encryption and decryption successful!\n");
        } else {
            System.out.println("Basic encryption and decryption failed!\n");
        }
        System.out.printf("\n");

        /*
         * 拓展功能测试：ASCII加密解密
         */
        String asciiPlaintext = "Hello, SAES!";
        int asciiKey = 0b1010101010101010;
        String asciiCiphertext = SAES.encryptASCII(asciiPlaintext, asciiKey);
        String decryptedText = SAES.decryptASCII(asciiCiphertext, asciiKey);
        System.out.printf("ASCII Test\n");
        System.out.printf("Plaintext:  %s\n", asciiPlaintext);
        System.out.printf("Key:       %16s\n", Integer.toBinaryString(asciiKey).replace(' ', '0'));
        System.out.printf("Ciphertext: %s\n", asciiCiphertext);
        System.out.printf("Decrypted:  %s\n", decryptedText);
        if (asciiPlaintext.equals(decryptedText)) {
            System.out.println("ASCII encryption and decryption successful!\n");
        } else {
            System.out.println("ASCII encryption and decryption failed!\n");
        }
        System.out.printf("\n");

        /*
         * 双重加密测试
         */
        int doublekey = 0b11001100110011001011101110111011;
        int doubleplaintext = 0b1101011100111001;
        int doubleciphertext = SAES.doubleEncrypt(doubleplaintext, doublekey);
        int doubledecrypted = SAES.doubleDecrypt(doubleciphertext, doublekey);
        System.out.printf("\nDouble Encryption Test\n");
        System.out.printf("Plaintext:  %16s\n", Integer.toBinaryString(doubleplaintext).replace(' ', '0'));
        System.out.printf("Key:       %32s\n", Integer.toBinaryString(doublekey).replace(' ', '0'));
        System.out.printf("Ciphertext: %16s\n", Integer.toBinaryString(doubleciphertext).replace(' ', '0'));
        System.out.printf("Decrypted:  %16s\n", Integer.toBinaryString(doubledecrypted).replace(' ', '0'));
        if (doubleplaintext == doubledecrypted) {
            System.out.println("Double encryption and decryption successful!\n");
        } else {
            System.out.println("Double encryption and decryption failed!\n");
        }
        System.out.printf("\n");
        /*
         * 中间相遇攻击,就使用上面的doubleplaintext和doubleciphertext进行攻击
         */
        List<Integer> recoveredKeys = SAES.MeetInTheMiddleAttack(doubleplaintext, doubleciphertext);
        System.out.printf("Meet-in-the-Middle Attack Test\n");
        System.out.printf("Recovered %d key pairs:\n", recoveredKeys.size() / 2);
        System.out.printf("\n");
        boolean keyFound = false;
        for (int combined : recoveredKeys) {
            int K1 = (combined >> 16) & 0xFFFF;
            int K2 = combined & 0xFFFF;
            int testCipher = SAES.doubleEncrypt(doubleplaintext, ((K1 << 16) | K2));
            if (testCipher == doubleciphertext) {
                System.out.printf("Matched K1=0x%04X K2=0x%04X%n", K1, K2);
                keyFound = true;
                break;
            }
        }
        if (keyFound) {
            System.out.println("Key pair verified successfully!\n");
        } else {
            System.out.println("Key pair verification failed!\n");
        }
        System.out.printf("\n");

        /*
         * 三重加密测试
         */
        int triplekey = 0b10111011101110111100110011001100;
        int tripleplaintext = 0b1010101010101010;
        int tripleciphertext = SAES.tripleEncrypt(tripleplaintext, triplekey);
        int tripledecrypted = SAES.tripleDecrypt(tripleciphertext, triplekey);
        System.out.printf("\nTriple Encryption Test\n");
        System.out.printf("Plaintext:  %16s\n", Integer.toBinaryString(tripleplaintext).replace(' ', '0'));
        System.out.printf("Key:       %32s\n", Integer.toBinaryString(triplekey).replace(' ', '0'));
        System.out.printf("Ciphertext: %16s\n", Integer.toBinaryString(tripleciphertext).replace(' ', '0'));
        System.out.printf("Decrypted:  %16s\n", Integer.toBinaryString(tripledecrypted).replace(' ', '0'));
        if (tripleplaintext == tripledecrypted) {
            System.out.println("Triple encryption and decryption successful!\n");
        } else {
            System.out.println("Triple encryption and decryption failed!\n");
        }
        System.out.printf("\n");

        System.out.printf("\n");

        /*
         * CBC模式测试
         */
        String cbcPlaintext = "1011101110111011";
        int cbcKey = 0b1111000011110000;
        String cbcCiphertext = SAES.cbcEncryptDigits(cbcPlaintext, cbcKey);
        String cbcDecrypted = SAES.cbcDecryptDigits(cbcCiphertext, cbcKey);
        System.out.printf("CBC Mode Test\n");
        System.out.printf("Plaintext:  %s\n", cbcPlaintext);
        System.out.printf("Key:       %16s\n", Integer.toBinaryString(cbcKey).replace(' ', '0'));
        System.out.printf("IV is prepended to ciphertext.\n");
        System.out.printf("Ciphertext: %s\n", cbcCiphertext);
        System.out.printf("Decrypted:  %s\n", cbcDecrypted);
        if (cbcPlaintext.equals(cbcDecrypted)) {
            System.out.println("CBC mode encryption and decryption successful!\n");
        } else {
            System.out.println("CBC mode encryption and decryption failed!\n");
        }

     }
}
