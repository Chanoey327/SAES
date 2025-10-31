/*
 * SAES - simple AES 算法实现
 * author: Yang yuhang, Wu Qilong
 * date: 2025-10-25
 */
import java.util.*;

public class SAES {
    /*
     * S盒
     */
    private static final int[][] S_Box ={
        {0x9, 0x4, 0xA, 0xB},
        {0xD, 0x1, 0x8, 0x5},
        {0x6, 0x2, 0x0, 0x3},
        {0xC, 0xE, 0xF, 0x7}
    };

    /*
     * 逆S盒
     */
    private static final int[][] Inverse_S_Box = {
        {0xA, 0x5, 0x9, 0xB},
        {0x1, 0x7, 0x8, 0xF},
        {0x6, 0x0, 0x2, 0x3},
        {0xC, 0x4, 0xD, 0xE}
    };

    /* 
     * RCON轮常数
    */
    private static final int RC1 = 0x80;
    private static final int RC2 = 0x30;

    private static final int[][] GF_MULT = {
            {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
            {0,1,2,3,4,5,6,7,8,9,0xA,0xB,0xC,0xD,0xE,0xF},
            {0,2,4,6,8,0xA,0xC,0xE,3,1,7,5,0xB,9,0xF,0xD},
            {0,3,6,5,0xC,0xF,0xA,9,0xB,8,0xD,0xE,7,4,1,2},
            {0,4,8,0xC,3,7,0xB,0xF,6,2,0xE,0xA,5,1,0xD,9},
            {0,5,0xA,0xF,7,2,0xD,8,0xE,0xB,4,1,9,0xC,3,6},
            {0,6,0xC,0xA,0xB,0xD,7,1,5,3,9,0xF,0xE,8,4,2},
            {0,7,0xE,9,0xF,8,1,6,0xD,0xA,3,4,2,5,0xC,0xB},
            {0,8,3,0xB,6,0xE,5,0xD,0xC,4,0xF,7,0xA,2,9,1},
            {0,9,1,8,2,0xB,3,0xA,4,0xD,5,0xC,6,0xF,7,0xE},
            {0,0xA,7,0xD,0xE,4,9,3,0xF,5,8,2,1,0xB,6,0xC},
            {0,0xB,5,0xE,0xA,1,0xF,4,7,0xC,2,9,0xD,6,8,3},
            {0,0xC,0xB,7,5,9,0xE,2,0xA,6,1,0xD,0xF,3,4,8},
            {0,0xD,9,4,1,0xC,8,5,2,0xF,0xB,6,3,0xE,0xA,7},
            {0,0xE,0xF,1,0xD,3,4,0xC,9,7,6,8,4,0xA,2,5},
            {0,0xF,0xD,2,9,6,2,0xB,1,0xE,0xC,3,8,7,5,0xA}
    };



    /*
     * GF(2^4)上的乘法
     */
    private static int gfMult(int a, int b){
        return GF_MULT[a & 0xF][b & 0xF] & 0xF;
    }


    /*
     * 秘钥加
     * 16位状态矩阵与16位轮秘钥逐位异或
     */
    private static int AddRoundKey(int state, int roundKey){
        //System.out.println(String.format("AddRoundKey => state=0x%04X roundKey=0x%04X, add = 0x%04X", state, roundKey, state ^ roundKey));
        return state ^ roundKey;
    }

    /*
     * 半字节替代
     * 使用S盒进行查表替换操作
     */
    private static int SubNibbles(int state){
        state = state & 0xFFFF;//保留state的有效16位
        int out = 0;
        for(int i=0;i<4;i++){
            int shift = (3 - i) * 4; // MSB-first
            int nibble = (state >> shift) & 0xF;
            int row = (nibble >> 2) & 0x3;
            int col = nibble & 0x3;
            int substituted = S_Box[row][col] & 0xF;
            out |= (substituted << shift);
        }
        //System.out.println(String.format("SubNibbles => state=0x%04X", out));
        return out & 0xFFFF;
    }

    /*
     * 逆半字节替代
     * 使用逆S盒进行查表替换操作
     */
    private static int InverseSubNibbles(int state){
        state = state & 0xFFFF;
        int out = 0;
        for(int i=0;i<4;i++){
            int shift = (3 - i) * 4; // MSB-first
            int nibble = (state >> shift) & 0xF;
            int row = (nibble >> 2) & 0x3;
            int col = nibble & 0x3;
            int substituted = Inverse_S_Box[row][col] & 0xF;
            out |= (substituted << shift);
        }
        return out & 0xFFFF;
    }

    /*
     * 行移位
     * 第二个半字节和第四个半字节交换
     */
    private static int ShiftRows(int state){
        state = state & 0xFFFF;
        int s0 = (state >> 12) & 0xF;
        int s1 = (state >> 8) & 0xF;
        int s2 = (state >> 4) & 0xF;
        int s3 = (state >> 0) & 0xF;
        state = (s0 << 12) | (s1 << 8) | (s3 << 4) | s2;
        //System.out.println(String.format("ShiftRows => state=0x%04X", state));
        return state;
    }

    /*
     * 逆行移位
     * 第二个半字节和第四个半字节交换
     */
    private static int InverseShiftRows(int state){
        //与ShiftRows操作相同
        return ShiftRows(state);
    }

    /*
     * 列混淆
     * 使用矩阵乘法(在GF(2^4)上)进行列混淆操作
     */
    private static int MixColumns(int state){
        state = state & 0xFFFF;
        int s0 = (state >> 12) & 0xF;
        int s1 = (state >> 8) & 0xF;
        int s2 = (state >> 4) & 0xF;
        int s3 = (state >> 0) & 0xF;

        int t0 = gfMult(1, s0) ^ gfMult(4, s2);
        int t1 = gfMult(1, s1) ^ gfMult(4, s3);
        int t2 = gfMult(4, s0) ^ gfMult(1, s2);
        int t3 = gfMult(4, s1) ^ gfMult(1, s3);

        state = (t0 << 12) | (t1 << 8) | (t2 << 4) | (t3 << 0);
        //System.out.println(String.format("MixColumns => state=0x%04X", state));
        return state;
    }

    /*
     * 逆列混淆
     * 使用逆矩阵乘法(在GF(2^4)上)进行逆列混淆操作
     */
    private static int InverseMixColumns(int state){
        state = state & 0xFFFF;
        int s0 = (state >> 12) & 0xF;
        int s1 = (state >> 8) & 0xF;
        int s2 = (state >> 4) & 0xF;
        int s3 = (state >> 0) & 0xF;

        int t0 = gfMult(9, s0) ^ gfMult(2, s2);
        int t1 = gfMult(9, s1) ^ gfMult(2, s3);
        int t2 = gfMult(2, s0) ^ gfMult(9, s2);
        int t3 = gfMult(2, s1) ^ gfMult(9, s3);

        state = (t0 << 12) | (t1 << 8) | (t2 << 4) | (t3 << 0);
        return state;
    }

    /*
     * 秘钥扩展
     * 使用预选计算好的RCON轮常数生成轮秘钥
     */
    private static int[] keyExpansion(int primaryKey) {
        int[] roundKeys = new int[3];
        roundKeys[0] = primaryKey & 0xFFFF;

        int w0 = (primaryKey >> 8) & 0xFF;
        int w1 = primaryKey & 0xFF;

        // rotate nibble (swap high/low nibble)
        int rotw1 = ((w1 << 4) | (w1 >>> 4)) & 0xFF;
        int high = (rotw1 >> 4) & 0xF;
        int low = rotw1 & 0xF;
        int subHigh = S_Box[(high >> 2) & 0x3][high & 0x3];
        int subLow = S_Box[(low >> 2) & 0x3][low & 0x3];
        int subw1 = (subHigh << 4) | subLow;

        int w2 = (w0 ^ subw1 ^ RC1) & 0xFF; // RC1 = 0x80
        int w3 = (w2 ^ w1) & 0xFF;
        roundKeys[1] = (w2 << 8) | w3;

        int rotw3 = ((w3 << 4) | (w3 >>> 4)) & 0xFF;
        high = (rotw3 >> 4) & 0xF;
        low = rotw3 & 0xF;
        subHigh = S_Box[(high >> 2) & 0x3][high & 0x3];
        subLow = S_Box[(low >> 2) & 0x3][low & 0x3];
        int subw3 = (subHigh << 4) | subLow;

        int w4 = (w2 ^ subw3 ^ RC2) & 0xFF; // RC2 = 0x30
        int w5 = (w4 ^ w3) & 0xFF;
        roundKeys[2] = (w4 << 8) | w5;

        //System.out.printf("KEYEXP key=0x%04X w0=0x%02X w1=0x%02X rotw1=0x%02X subw1=0x%02X w2=0x%02X w3=0x%02X w4=0x%02X w5=0x%02X RK1=0x%04X RK2=0x%04X%n",
        //    primaryKey & 0xFFFF, w0, w1, rotw1, subw1, w2, w3, w4, w5, roundKeys[1] & 0xFFFF, roundKeys[2] & 0xFFFF);
        return roundKeys;
    }


    /*
     * 加密
     */
    public static int encrypt(int plaintext, int primaryKey){
        int[] roundKeys = keyExpansion(primaryKey);
        // 初始轮秘钥加
        int state = AddRoundKey(plaintext, roundKeys[0]);
        // 第一轮
        state = SubNibbles(state);
        state = ShiftRows(state);
        state = MixColumns(state);
        state = AddRoundKey(state, roundKeys[1]);
        // 第二轮
        state = SubNibbles(state);
        state = ShiftRows(state);
        state = AddRoundKey(state, roundKeys[2]);
        return state & 0xFFFF;
    }

    /*
     * 解密
     */
    public static int decrypt(int ciphertext, int primaryKey){
        int[] roundKeys = keyExpansion(primaryKey);
        int state = AddRoundKey(ciphertext, roundKeys[2]);
        state = InverseShiftRows(state);
        state = InverseSubNibbles(state);
        state = AddRoundKey(state, roundKeys[1]);
        state = InverseMixColumns(state);
        state = InverseShiftRows(state);
        state = InverseSubNibbles(state);
        state = AddRoundKey(state, roundKeys[0]);
        return state & 0xFFFF;
    }

    /*
     * 获取轮秘钥1
     */
    public static int getRoundKey1(int primaryKey){
        int[] roundKeys = keyExpansion(primaryKey);
        return roundKeys[1];
    }

    /*
     * 获取轮秘钥2
     */
    public static int getRoundKey2(int primaryKey){
        int[] roundKeys = keyExpansion(primaryKey);
        return roundKeys[2];
    }

    /*
     * 拓展功能——ASCII编码字符串加密
     * 分组长度为2字节(16位)
     */
    public static String encryptASCII(String plaintext, int primaryKey){
        StringBuilder ciphertext = new StringBuilder();
        for(int i=0;i<plaintext.length();i+=2){
            int block = 0;
            block |= (plaintext.charAt(i) & 0xFF) << 8;
            if(i+1 < plaintext.length()){
                block |= (plaintext.charAt(i+1) & 0xFF);
            }
            int encryptedBlock = encrypt(block, primaryKey);
            ciphertext.append(String.format("%04X", encryptedBlock));
        }
        return ciphertext.toString();
    }

    /*
     * 拓展功能——ASCII编码字符串解密
     * 分组长度为2字节(16位)
     */
    public static String decryptASCII(String ciphertext, int primaryKey){
        StringBuilder plaintext = new StringBuilder();
        for(int i=0;i<ciphertext.length();i+=4){
            String blockStr = ciphertext.substring(i, Math.min(i+4, ciphertext.length()));
            int block = Integer.parseInt(blockStr, 16);
            int decryptedBlock = decrypt(block, primaryKey);
            plaintext.append((char)((decryptedBlock >> 8) & 0xFF));
            plaintext.append((char)(decryptedBlock & 0xFF));
        }
        return plaintext.toString();
    }

    /*
     * 双重加密
     * K1加密后再用K2解密(输入的密钥为32位，前16位为K1，后16位为K2)
     */
    public static int doubleEncrypt(int plaintext, int primaryKey){
        int K1 = (primaryKey >> 16) & 0xFFFF;
        int K2 = primaryKey & 0xFFFF;
        int firstEncryption = encrypt(plaintext, K1);
        int doubleEncrypted = decrypt(firstEncryption, K2);
        return doubleEncrypted & 0xFFFF;
    }

    /*
     * 双重解密
     * K2加密后再用K1解密(输入的密钥为32位，前16位为K1，后16位为K2)
     */
    public static int doubleDecrypt(int ciphertext, int primaryKey){
        int K1 = (primaryKey >> 16) & 0xFFFF;
        int K2 = primaryKey & 0xFFFF;
        int firstDecryption = encrypt(ciphertext, K2);
        int doubleDecrypted = decrypt(firstDecryption, K1);
        return doubleDecrypted & 0xFFFF;
    }

    /*
     * 针对双重加密的中间相遇攻击
     */
    public static List<Integer> MeetInTheMiddleAttack(int plaintext, int ciphertext){
        Map<Integer, Integer> forwardMap = new HashMap<>();
        // 前向计算所有可能的中间值
        for(int K1 = 0; K1 <= 0xFFFF; K1++){
            int midValue = encrypt(plaintext, K1);
            forwardMap.put(midValue, K1);
        }
        List<Integer> possibleKeys = new ArrayList<>();
        // 反向计算并查找匹配的中间值
        for(int K2 = 0; K2 <= 0xFFFF; K2++){
            int midValue = decrypt(ciphertext, K2);
            if(forwardMap.containsKey(midValue)){
                int K1 = forwardMap.get(midValue);
                int combinedKey = (K1 << 16) | K2;
                possibleKeys.add(combinedKey);
            }
        }
        return possibleKeys;
    }

    /*
     * 三重加密
     * K1加密后用K2解密再用K1加密(输入的密钥为48bit = 16bit K1 + 16bit K2 + 16bit K1)
     */
    public static int tripleEncrypt(int plaintext, int primaryKey){
        int K1 = (primaryKey >> 32) & 0xFFFF;
        int K2 = (primaryKey >> 16) & 0xFFFF;
        int firstEncryption = encrypt(plaintext, K1);
        int middleDecryption = decrypt(firstEncryption, K2);
        int tripleEncrypted = encrypt(middleDecryption, K1);
        return tripleEncrypted & 0xFFFF;
    }

    /*
     * 三重解密
     * K1解密后用K2加密再用K1解密(输入的密钥为48bit = 16bit K1 + 16bit K2 + 16bit K1)
     */
    public static int tripleDecrypt(int ciphertext, int primaryKey){
        int K1 = (primaryKey >> 32) & 0xFFFF;
        int K2 = (primaryKey >> 16) & 0xFFFF;
        int firstDecryption = decrypt(ciphertext, K1);
        int middleEncryption = encrypt(firstDecryption, K2);
        int tripleDecrypted = decrypt(middleEncryption, K1);
        return tripleDecrypted & 0xFFFF;
    }
    
    /*
     * 生成随机16位秘钥
     */
    private static final java.security.SecureRandom random = new java.security.SecureRandom();

    private static int generateIV() {
        return random.nextInt(0xFFFF + 1) & 0xFFFF;
    }

    /*
     * CBC模式加密
     * 明文仍然是16位块，初始向量IV为16位
     */
    public static String cbcEncryptDigits(String digits, int primaryKey) {
        if (digits == null) throw new IllegalArgumentException("digits == null");
        // 验证只含数字
        if (!digits.matches("\\d*")) throw new IllegalArgumentException("plaintext must contain digits only");

        int iv = generateIV();
        int origLen = digits.length();
        // pad 至 4 的倍数，用 '0' 补齐（解密时依据 origLen 截断）
        int pad = (4 - (origLen % 4)) % 4;
        StringBuilder sb = new StringBuilder(digits);
        for (int i = 0; i < pad; i++) sb.append('0');
        String padded = sb.toString();

        StringBuilder ct = new StringBuilder();
        // 前缀：IV (4 hex) + 原始长度 (4 hex)
        ct.append(String.format("%04X", iv));
        ct.append(String.format("%04X", origLen & 0xFFFF));

        int prev = iv & 0xFFFF;
        for (int i = 0; i < padded.length(); i += 4) {
            String chunk = padded.substring(i, i + 4);
            int block = Integer.parseInt(chunk); // 0..9999 fits in 16-bit
            block &= 0xFFFF;
            int xored = (block ^ prev) & 0xFFFF;
            int enc = encrypt(xored, primaryKey) & 0xFFFF;
            ct.append(String.format("%04X", enc));
            prev = enc;
        }
        return ct.toString();
    }

    /*
     * CBC模式解密
     * 密文仍然是16位块，初始向量IV为16位
     */
     public static String cbcDecryptDigits(String ciphertextHex, int primaryKey) {
        if (ciphertextHex == null || ciphertextHex.length() < 8) throw new IllegalArgumentException("ciphertext too short");
        // 解析 IV 与原始长度
        int iv = Integer.parseInt(ciphertextHex.substring(0,4), 16) & 0xFFFF;
        int origLen = Integer.parseInt(ciphertextHex.substring(4,8), 16) & 0xFFFF;

        StringBuilder out = new StringBuilder();
        int prev = iv;
        for (int i = 8; i + 4 <= ciphertextHex.length(); i += 4) {
            int enc = Integer.parseInt(ciphertextHex.substring(i, i + 4), 16) & 0xFFFF;
            int dec = decrypt(enc, primaryKey) & 0xFFFF;
            int plainBlock = (dec ^ prev) & 0xFFFF;
            prev = enc;
            // plainBlock 表示 0..9999 的十进制块，输出为 4 位十进制（左补零）
            out.append(String.format("%04d", plainBlock));
        }
        // 截断到原始长度并返回
        if (origLen <= out.length()) {
            return out.substring(0, origLen);
        } else {
            // 不太可能，但若长度不够则报错
            throw new IllegalStateException("decrypted length shorter than original length");
        }
    }

    /*
     * 简单篡改函数：对第一个数据分组（跳过 IV+len）翻转最低位，返回新的密文 hex
     */
    public static String tamperCiphertextDigits(String ciphertextHex) {
        if (ciphertextHex == null || ciphertextHex.length() <= 8) return ciphertextHex;
        int dataStart = 8;
        String firstBlockHex = ciphertextHex.substring(dataStart, dataStart + 4);
        int blk = Integer.parseInt(firstBlockHex, 16);
        blk ^= 0x0001; // 翻转最低位
        StringBuilder sb = new StringBuilder();
        sb.append(ciphertextHex.substring(0, dataStart));
        sb.append(String.format("%04X", blk & 0xFFFF));
        if (ciphertextHex.length() > dataStart + 4) sb.append(ciphertextHex.substring(dataStart + 4));
        return sb.toString();
    }
}
