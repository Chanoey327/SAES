import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.FileWriter;
import java.io.IOException;
import java.util.List;

/**
 * SAES算法图形用户界面
 * 提供独立的GUI界面来使用现有的SAES算法功能
 */
public class SAESGui extends JFrame {
    
    // GUI组件
    private JTextField plaintextField;
    private JTextField keyField;
    private JTextField ciphertextField;
    private JTextArea resultArea;
    private JComboBox<String> operationCombo;
    private JComboBox<String> modeCombo;
    private JButton executeButton;
    private JButton clearButton;
    private JButton exportButton;
    private JProgressBar progressBar;
    private JLabel statusLabel;
    
    // 操作模式
    private static final String[] OPERATIONS = {"基本加密", "基本解密", "ASCII加密", "ASCII解密", 
                                               "双重加密", "双重解密", "三重加密", "三重解密", 
                                               "CBC加密", "CBC解密", "中间相遇攻击"};
    
    public SAESGui() {
        initializeGUI();
        setupEventHandlers();
    }
    
    /**
     * 初始化GUI界面
     */
    private void initializeGUI() {
        setTitle("SAES算法图形界面");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLayout(new BorderLayout());
        
        // 创建主面板
        JPanel mainPanel = new JPanel(new BorderLayout(10, 10));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // 参数配置面板
        JPanel paramPanel = createParameterPanel();
        
        // 控制面板
        JPanel controlPanel = createControlPanel();
        
        // 结果显示面板
        JPanel resultPanel = createResultPanel();
        
        // 状态面板
        JPanel statusPanel = createStatusPanel();
        
        // 布局
        mainPanel.add(paramPanel, BorderLayout.NORTH);
        mainPanel.add(controlPanel, BorderLayout.CENTER);
        mainPanel.add(resultPanel, BorderLayout.SOUTH);
        
        add(mainPanel, BorderLayout.CENTER);
        add(statusPanel, BorderLayout.SOUTH);
        
        // 设置窗口属性
        setSize(800, 600);
        setLocationRelativeTo(null);
        setResizable(true);
    }
    
    /**
     * 创建参数配置面板
     */
    private JPanel createParameterPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(new TitledBorder("算法参数配置"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        
        // 操作类型选择
        gbc.gridx = 0; gbc.gridy = 0;
        panel.add(new JLabel("操作类型:"), gbc);
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL;
        operationCombo = new JComboBox<>(OPERATIONS);
        panel.add(operationCombo, gbc);
        
        // 明文/密文输入
        gbc.gridx = 0; gbc.gridy = 1; gbc.fill = GridBagConstraints.NONE;
        panel.add(new JLabel("明文/密文:"), gbc);
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL;
        plaintextField = new JTextField(20);
        panel.add(plaintextField, gbc);
        
        // 密钥输入
        gbc.gridx = 0; gbc.gridy = 2; gbc.fill = GridBagConstraints.NONE;
        panel.add(new JLabel("密钥:"), gbc);
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL;
        keyField = new JTextField(20);
        panel.add(keyField, gbc);
        
        // 密文输出（用于解密操作）
        gbc.gridx = 0; gbc.gridy = 3; gbc.fill = GridBagConstraints.NONE;
        panel.add(new JLabel("密文输出:"), gbc);
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL;
        ciphertextField = new JTextField(20);
        ciphertextField.setEditable(false);
        panel.add(ciphertextField, gbc);
        
        return panel;
    }
    
    /**
     * 创建控制面板
     */
    private JPanel createControlPanel() {
        JPanel panel = new JPanel(new FlowLayout());
        panel.setBorder(new TitledBorder("操作控制"));
        
        executeButton = new JButton("执行");
        executeButton.setPreferredSize(new Dimension(100, 30));
        
        clearButton = new JButton("清空");
        clearButton.setPreferredSize(new Dimension(100, 30));
        
        exportButton = new JButton("导出结果");
        exportButton.setPreferredSize(new Dimension(100, 30));
        
        panel.add(executeButton);
        panel.add(clearButton);
        panel.add(exportButton);
        
        return panel;
    }
    
    /**
     * 创建结果显示面板
     */
    private JPanel createResultPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(new TitledBorder("执行结果"));
        
        resultArea = new JTextArea(15, 50);
        resultArea.setEditable(false);
        resultArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        
        JScrollPane scrollPane = new JScrollPane(resultArea);
        panel.add(scrollPane, BorderLayout.CENTER);
        
        return panel;
    }
    
    /**
     * 创建状态面板
     */
    private JPanel createStatusPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        
        statusLabel = new JLabel("就绪");
        progressBar = new JProgressBar();
        progressBar.setStringPainted(true);
        
        panel.add(statusLabel, BorderLayout.WEST);
        panel.add(progressBar, BorderLayout.CENTER);
        
        return panel;
    }
    
    /**
     * 设置事件处理器
     */
    private void setupEventHandlers() {
        executeButton.addActionListener(new ExecuteActionListener());
        clearButton.addActionListener(e -> clearFields());
        exportButton.addActionListener(new ExportActionListener());
        
        // 操作类型改变时更新界面
        operationCombo.addActionListener(e -> updateUIForOperation());
    }
    
    /**
     * 根据操作类型更新界面
     */
    private void updateUIForOperation() {
        String operation = (String) operationCombo.getSelectedItem();
        
        // 根据不同操作类型调整界面提示
        if (operation.contains("解密")) {
            plaintextField.setBorder(BorderFactory.createTitledBorder("密文输入"));
        } else {
            plaintextField.setBorder(BorderFactory.createTitledBorder("明文输入"));
        }
        
        if (operation.contains("ASCII")) {
            keyField.setToolTipText("请输入16位二进制密钥（如：1010101010101010）");
        } else if (operation.contains("双重")) {
            keyField.setToolTipText("请输入32位二进制密钥（前16位K1，后16位K2）");
        } else if (operation.contains("三重")) {
            keyField.setToolTipText("请输入48位二进制密钥（K1-K2-K1格式）");
        } else {
            keyField.setToolTipText("请输入16位二进制密钥");
        }
    }
    
    /**
     * 清空所有输入字段
     */
    private void clearFields() {
        plaintextField.setText("");
        keyField.setText("");
        ciphertextField.setText("");
        resultArea.setText("");
        statusLabel.setText("已清空");
        progressBar.setValue(0);
    }
    
    /**
     * 执行按钮事件处理器
     */
    private class ExecuteActionListener implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            SwingWorker<String, Void> worker = new SwingWorker<String, Void>() {
                @Override
                protected String doInBackground() throws Exception {
                    return executeOperation();
                }
                
                @Override
                protected void done() {
                    try {
                        String result = get();
                        resultArea.setText(result);
                        statusLabel.setText("执行完成");
                        progressBar.setValue(100);
                    } catch (Exception ex) {
                        resultArea.setText("执行错误: " + ex.getMessage());
                        statusLabel.setText("执行失败");
                        progressBar.setValue(0);
                    }
                }
            };
            
            statusLabel.setText("正在执行...");
            progressBar.setValue(50);
            worker.execute();
        }
    }
    
    /**
     * 执行具体的算法操作
     */
    private String executeOperation() throws Exception {
        String operation = (String) operationCombo.getSelectedItem();
        String input = plaintextField.getText().trim();
        String keyStr = keyField.getText().trim();
        
        if (input.isEmpty() || keyStr.isEmpty()) {
            throw new IllegalArgumentException("请输入完整的参数");
        }
        
        StringBuilder result = new StringBuilder();
        result.append("=== SAES算法执行结果 ===\n");
        result.append("操作类型: ").append(operation).append("\n");
        result.append("输入数据: ").append(input).append("\n");
        result.append("密钥: ").append(keyStr).append("\n");
        result.append("执行时间: ").append(new java.util.Date()).append("\n\n");
        
        try {
            switch (operation) {
                case "基本加密":
                    result.append(performBasicEncryption(input, keyStr));
                    break;
                case "基本解密":
                    result.append(performBasicDecryption(input, keyStr));
                    break;
                case "ASCII加密":
                    result.append(performASCIIEncryption(input, keyStr));
                    break;
                case "ASCII解密":
                    result.append(performASCIIDecryption(input, keyStr));
                    break;
                case "双重加密":
                    result.append(performDoubleEncryption(input, keyStr));
                    break;
                case "双重解密":
                    result.append(performDoubleDecryption(input, keyStr));
                    break;
                case "三重加密":
                    result.append(performTripleEncryption(input, keyStr));
                    break;
                case "三重解密":
                    result.append(performTripleDecryption(input, keyStr));
                    break;
                case "CBC加密":
                    result.append(performCBCEncryption(input, keyStr));
                    break;
                case "CBC解密":
                    result.append(performCBCDecryption(input, keyStr));
                    break;
                case "中间相遇攻击":
                    result.append(performMeetInTheMiddleAttack(input, keyStr));
                    break;
                default:
                    throw new IllegalArgumentException("不支持的操作类型");
            }
        } catch (Exception ex) {
            result.append("执行错误: ").append(ex.getMessage()).append("\n");
            throw ex;
        }
        
        return result.toString();
    }
    
    // 各种算法操作的实现方法
    private String performBasicEncryption(String input, String keyStr) {
        int plaintext = parseBinaryInput(input);
        int key = parseBinaryInput(keyStr);
        int ciphertext = SAES.encrypt(plaintext, key);
        
        String result = String.format("明文: %s (%d)\n", input, plaintext);
        result += String.format("密钥: %s (%d)\n", keyStr, key);
        result += String.format("密文: %s (%d)\n", Integer.toBinaryString(ciphertext), ciphertext);
        result += String.format("轮密钥K1: %s\n", Integer.toBinaryString(SAES.getRoundKey1(key)));
        result += String.format("轮密钥K2: %s\n", Integer.toBinaryString(SAES.getRoundKey2(key)));
        
        ciphertextField.setText(Integer.toBinaryString(ciphertext));
        return result;
    }
    
    private String performBasicDecryption(String input, String keyStr) {
        int ciphertext = parseBinaryInput(input);
        int key = parseBinaryInput(keyStr);
        int plaintext = SAES.decrypt(ciphertext, key);
        
        String result = String.format("密文: %s (%d)\n", input, ciphertext);
        result += String.format("密钥: %s (%d)\n", keyStr, key);
        result += String.format("明文: %s (%d)\n", Integer.toBinaryString(plaintext), plaintext);
        
        ciphertextField.setText(Integer.toBinaryString(plaintext));
        return result;
    }
    
    private String performASCIIEncryption(String input, String keyStr) {
        int key = parseBinaryInput(keyStr);
        String ciphertext = SAES.encryptASCII(input, key);
        
        String result = String.format("ASCII明文: %s\n", input);
        result += String.format("密钥: %s (%d)\n", keyStr, key);
        result += String.format("密文(十六进制): %s\n", ciphertext);
        
        ciphertextField.setText(ciphertext);
        return result;
    }
    
    private String performASCIIDecryption(String input, String keyStr) {
        int key = parseBinaryInput(keyStr);
        String plaintext = SAES.decryptASCII(input, key);
        
        String result = String.format("密文(十六进制): %s\n", input);
        result += String.format("密钥: %s (%d)\n", keyStr, key);
        result += String.format("ASCII明文: %s\n", plaintext);
        
        ciphertextField.setText(plaintext);
        return result;
    }
    
    private String performDoubleEncryption(String input, String keyStr) {
        int plaintext = parseBinaryInput(input);
        int key = (int) Long.parseLong(keyStr, 2);
        int ciphertext = SAES.doubleEncrypt(plaintext, key);
        
        String result = String.format("明文: %s (%d)\n", input, plaintext);
        result += String.format("32位密钥: %s\n", keyStr);
        result += String.format("K1: %s\n", keyStr.substring(0, 16));
        result += String.format("K2: %s\n", keyStr.substring(16));
        result += String.format("双重加密结果: %s (%d)\n", Integer.toBinaryString(ciphertext), ciphertext);
        
        ciphertextField.setText(Integer.toBinaryString(ciphertext));
        return result;
    }
    
    private String performDoubleDecryption(String input, String keyStr) {
        int ciphertext = parseBinaryInput(input);
        int key = (int) Long.parseLong(keyStr, 2);
        int plaintext = SAES.doubleDecrypt(ciphertext, key);
        
        String result = String.format("密文: %s (%d)\n", input, ciphertext);
        result += String.format("32位密钥: %s\n", keyStr);
        result += String.format("双重解密结果: %s (%d)\n", Integer.toBinaryString(plaintext), plaintext);
        
        ciphertextField.setText(Integer.toBinaryString(plaintext));
        return result;
    }
    
    private String performTripleEncryption(String input, String keyStr) {
        int plaintext = parseBinaryInput(input);
        long key = Long.parseLong(keyStr, 2);
        int ciphertext = SAES.tripleEncrypt(plaintext, (int) key);
        
        String result = String.format("明文: %s (%d)\n", input, plaintext);
        result += String.format("48位密钥: %s\n", keyStr);
        result += String.format("三重加密结果: %s (%d)\n", Integer.toBinaryString(ciphertext), ciphertext);
        
        ciphertextField.setText(Integer.toBinaryString(ciphertext));
        return result;
    }
    
    private String performTripleDecryption(String input, String keyStr) {
        int ciphertext = parseBinaryInput(input);
        long key = Long.parseLong(keyStr, 2);
        int plaintext = SAES.tripleDecrypt(ciphertext, (int) key);
        
        String result = String.format("密文: %s (%d)\n", input, ciphertext);
        result += String.format("48位密钥: %s\n", keyStr);
        result += String.format("三重解密结果: %s (%d)\n", Integer.toBinaryString(plaintext), plaintext);
        
        ciphertextField.setText(Integer.toBinaryString(plaintext));
        return result;
    }
    
    private String performCBCEncryption(String input, String keyStr) {
        int key = parseBinaryInput(keyStr);
        String ciphertext = SAES.cbcEncryptDigits(input, key);
        
        String result = String.format("数字明文: %s\n", input);
        result += String.format("密钥: %s (%d)\n", keyStr, key);
        result += String.format("CBC加密结果: %s\n", ciphertext);
        result += "注: 前8位为IV和原始长度信息\n";
        
        ciphertextField.setText(ciphertext);
        return result;
    }
    
    private String performCBCDecryption(String input, String keyStr) {
        int key = parseBinaryInput(keyStr);
        String plaintext = SAES.cbcDecryptDigits(input, key);
        
        String result = String.format("CBC密文: %s\n", input);
        result += String.format("密钥: %s (%d)\n", keyStr, key);
        result += String.format("解密结果: %s\n", plaintext);
        
        ciphertextField.setText(plaintext);
        return result;
    }
    
    private String performMeetInTheMiddleAttack(String plaintext, String ciphertext) {
        int pt = parseBinaryInput(plaintext);
        int ct = parseBinaryInput(ciphertext);
        
        List<Integer> possibleKeys = SAES.MeetInTheMiddleAttack(pt, ct);
        
        StringBuilder result = new StringBuilder();
        result.append(String.format("明文: %s (%d)\n", plaintext, pt));
        result.append(String.format("密文: %s (%d)\n", ciphertext, ct));
        result.append(String.format("找到 %d 个可能的密钥对:\n\n", possibleKeys.size()));
        
        for (int i = 0; i < Math.min(10, possibleKeys.size()); i++) {
            int combined = possibleKeys.get(i);
            int K1 = (combined >> 16) & 0xFFFF;
            int K2 = combined & 0xFFFF;
            result.append(String.format("密钥对 %d: K1=%s, K2=%s\n", 
                i + 1, Integer.toBinaryString(K1), Integer.toBinaryString(K2)));
        }
        
        if (possibleKeys.size() > 10) {
            result.append(String.format("... 还有 %d 个密钥对\n", possibleKeys.size() - 10));
        }
        
        return result.toString();
    }
    
    /**
     * 解析二进制输入
     */
    private int parseBinaryInput(String input) {
        try {
            return Integer.parseInt(input, 2);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("无效的二进制输入: " + input);
        }
    }
    
    /**
     * 导出结果事件处理器
     */
    private class ExportActionListener implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            if (resultArea.getText().trim().isEmpty()) {
                JOptionPane.showMessageDialog(SAESGui.this, "没有可导出的结果", "提示", JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setSelectedFile(new java.io.File("SAES_Result.txt"));
            
            if (fileChooser.showSaveDialog(SAESGui.this) == JFileChooser.APPROVE_OPTION) {
                try {
                    FileWriter writer = new FileWriter(fileChooser.getSelectedFile());
                    writer.write(resultArea.getText());
                    writer.close();
                    JOptionPane.showMessageDialog(SAESGui.this, "结果已导出", "成功", JOptionPane.INFORMATION_MESSAGE);
                } catch (IOException ex) {
                    JOptionPane.showMessageDialog(SAESGui.this, "导出失败: " + ex.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
                }
            }
        }
    }
    
    /**
     * 主方法
     */
    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            new SAESGui().setVisible(true);
        });
    }
}