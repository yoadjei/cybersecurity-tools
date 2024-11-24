

### **FinSecGuard: Financial Security Guard Tool**

**FinSecGuard** is a cybersecurity tool designed to enhance financial security by combining **AES encryption**, **password strength analysis**, **network sniffing**, and **fraud detection**. It simulates a basic financial risk management scenario to ensure that financial data is encrypted and secure from malicious attacks.

---

### **Features**

- **AES Encryption & Decryption**  
  Securely encrypt and decrypt sensitive financial data, such as account information and balances.  

- **Password Strength Analyzer**  
  Evaluate the strength of passwords based on length, complexity, and variety.  

- **Network Sniffer for Fraud Detection**  
  Capture and analyze network traffic to detect unusual transactions and potential fraud using IP address analysis.  

- **Simulated Transaction Fraud Detection**  
  Simulate financial transactions and detect fraudulent activity based on transaction amount and source.  

---

### **How to Use**

1. **Clone the repository**  

   First, clone the **FinSecGuard** repository:  
   ```bash
   git clone https://github.com/yourusername/finsecguard.git  
   cd finsecguard  
   ```

2. **Install Required Libraries**  

   Install the necessary libraries using the following command:  
   ```bash
   pip install -r requirements.txt  
   ```  
   Alternatively, you can install the required libraries individually:  
   ```bash
   pip install pycryptodome scapy  
   ```

3. **Run the Script**  

   Execute the script to simulate the financial security process:  
   ```bash
   python finsecguard.py  
   ```

4. **View Results**  
   - The script will **encrypt and decrypt financial data**.  
   - It will **check the strength of a sample password**.  
   - It will **simulate network sniffing to detect unusual traffic**.  
   - It will **simulate financial transactions and flag any suspicious activity**.  

---

### **Technical Details**

- **Python Version**: Python 3.6 or higher  
- **Encryption**: AES encryption with CBC mode for securing sensitive data.  
- **Password Analysis**: Evaluates password strength based on length, uppercase letters, and digits.  
- **Network Sniffing**: Uses Scapy to capture and analyze network packets for unusual activity.  
- **Fraud Detection**: Detects large or suspicious financial transactions based on predefined thresholds.  

---

### **Required Libraries**

To run the tool, ensure that the following libraries are installed:  
- **PyCryptodome**: For AES encryption and decryption  
- **Scapy**: For network sniffing and packet analysis  

You can install them using:  
```bash
pip install pycryptodome scapy  
```

---

### **Example Output**

When you run **FinSecGuard**, you will see output similar to the following:  
```
Encrypted Financial Data: b'...encrypted data bytes...'  
Decrypted Financial Data: Account_Number: 1234567890, Balance: $10000  
Password Strength: Strong  
Starting network sniffing...  
Packet detected from 192.168.1.2 to 192.168.1.1  
Warning: Unusual source IP detected!  
Simulated transaction: {'amount': 1500, 'ip': '192.168.1.2', 'type': 'transfer'}  
Simulated transaction: {'amount': 4500, 'ip': '192.168.1.3', 'type': 'withdrawal'}  
Warning: Large transaction detected!  
```

---

### **Disclaimer**

This tool is intended for **educational and personal use only**. It is not suitable for production environments. The **network sniffing feature** requires administrative (root) access to capture packets, and is intended to simulate a basic financial risk management scenario for learning purposes.

---

### **License**

This project is licensed under the **MIT License** - see the LICENSE file for details.  

Feel free to modify the tool to fit your use case, and contribute if you have ideas for improvements!  
