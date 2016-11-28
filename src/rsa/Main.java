
package rsa;

/**
 * The Class Main for RSA encryption.
 * 
 * @author Islam Dudaev(CMP)
 * @since 24/03/2014
 */


// Draw graphics and create graphical user interfaces; 
// AWT stands for Abstract Windowing Toolkit.
import java.awt.BorderLayout;
import java.awt.EventQueue;
import java.awt.Font;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
///////////////////////////////////////////////////////////////////////////

// Perform a wide variety of input and output functions.
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectInputStream;
//////////////////////////////////////////////////////////////////////////

// Enforce security restrictions.
import java.security.PrivateKey;
import java.security.PublicKey;
//////////////////////////////////////////////////////////////////////////

// Create graphical user interfaces with components that extend the AWT capabilities.
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingConstants;
import javax.swing.UIManager;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
///////////////////////////////////////////////////////////////////////////

public class Main extends JFrame {

    /**
     * The content pane.
     */
    private JPanel contentPane;
    /**
     * The text area_1.
     */
    private JTextArea textArea_1;
    /**
     * The text area.
     */
    private JTextArea textArea;

    /**
     * Launch the application.
     *
     * @param args the arguments
     */
    public static void main(String[] args) {
        //for GUI implementation, event thread.
        EventQueue.invokeLater(new Runnable() {
            public void run() {
                try {
                    Main frame = new Main();
                    frame.setVisible(true); //show the frame
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
    }

    /**
     * Create the frame.
     */
    public Main() {
        try {
            if (!RSAEncryption.areKeysPresent()) {
                // Method generates a pair of keys using the RSA algorithm and stores it
                // in their respective files
                RSAEncryption.generateKey();
            }
            setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            setBounds(100, 100, 650, 500);
            contentPane = new JPanel();
            contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
            setContentPane(contentPane);
            contentPane.setLayout(new BorderLayout(0, 0));

            JPanel panel_2 = new JPanel();
            contentPane.add(panel_2);
            panel_2.setLayout(new GridLayout(0, 1, 0, 0));

            JPanel panel = new JPanel();
            panel_2.add(panel);
            panel.setLayout(new BorderLayout(0, 0));

            JLabel lblNewLabel = new JLabel("RSA Cryptography");
            lblNewLabel.setFont(new Font("Tahoma", Font.PLAIN, 28));
            lblNewLabel.setHorizontalAlignment(SwingConstants.CENTER);
            panel.add(lblNewLabel, BorderLayout.NORTH);

            JPanel panel_4 = new JPanel();
            panel_4.setBorder(new TitledBorder(UIManager.getBorder("TitledBorder.border"), "PLAIN TEXT", TitledBorder.LEADING, TitledBorder.TOP, null, null));
            panel.add(panel_4, BorderLayout.CENTER);
            panel_4.setLayout(new BorderLayout(0, 0));

            textArea = new JTextArea();

            JScrollPane scrollPane = new JScrollPane(textArea);
            panel_4.add(scrollPane);

            JPanel panel_1 = new JPanel();
            panel_2.add(panel_1);
            panel_1.setLayout(new BorderLayout(0, 0));

            JPanel panel_3 = new JPanel();
            panel_1.add(panel_3, BorderLayout.NORTH);

            JButton btnEncrypt = new JButton("Encrypt");
            btnEncrypt.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent arg0) {
                    try {
                        encryptedData = encrypt(textArea.getText());
                        textArea_1.setText(encryptedData.toString());

                    } catch (FileNotFoundException e) {
                        e.printStackTrace();
                    } catch (ClassNotFoundException e) {
                        e.printStackTrace();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            });
            panel_3.add(btnEncrypt);

            JButton btnDecrypt = new JButton("Decrypt");
            btnDecrypt.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    try {
                        textArea.setText(decrypt(encryptedData));
                    } catch (FileNotFoundException e1) {
                        e1.printStackTrace();
                    } catch (ClassNotFoundException e1) {
                        e1.printStackTrace();
                    } catch (IOException e1) {
                        e1.printStackTrace();
                    }
                }
            });
            panel_3.add(btnDecrypt);

            JButton btnClear = new JButton("Clear");
            btnClear.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    textArea.setText("");
                    textArea_1.setText("");
                }
            });
            panel_3.add(btnClear);

            JPanel panel_5 = new JPanel();
            panel_5.setBorder(new TitledBorder(UIManager.getBorder("TitledBorder.border"), "ENCRYPTED TEXT", TitledBorder.LEADING, TitledBorder.TOP, null, null));
            panel_1.add(panel_5, BorderLayout.CENTER);
            panel_5.setLayout(new BorderLayout(0, 0));

            textArea_1 = new JTextArea();
            textArea_1.setEditable(false);

            JScrollPane scrollPane_1 = new JScrollPane(textArea_1);
            panel_5.add(scrollPane_1);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
    /**
     * The encrypted data.
     */
    String encryptedData;

    /**
     * Encrypt.
     *
     * @param originalText the original text
     * @return the string
     * @throws FileNotFoundException the file not found exception
     * @throws IOException Signals that an I/O exception has occurred.
     * @throws ClassNotFoundException the class not found exception
     */
    public String encrypt(String originalText) throws FileNotFoundException, IOException, ClassNotFoundException {
        ObjectInputStream inputStream = null;

        // Encrypt the string using the public key
        inputStream = new ObjectInputStream(new FileInputStream(RSAEncryption.PUBLIC_KEY));
        final PublicKey publicKey = (PublicKey) inputStream.readObject();
        final String cipherText = RSAEncryption.encrypt(originalText, publicKey);
        return cipherText;
    }

    /**
     * Decrypt.
     *
     * @param cipherText the cipher text
     * @return the string
     * @throws FileNotFoundException the file not found exception
     * @throws IOException Signals that an I/O exception has occurred.
     * @throws ClassNotFoundException the class not found exception
     */
    public String decrypt(String cipherText) throws FileNotFoundException, IOException, ClassNotFoundException {
        ObjectInputStream inputStream = new ObjectInputStream(new FileInputStream(RSAEncryption.PRIVATE_KEY));
        final PrivateKey privateKey = (PrivateKey) inputStream.readObject();
        final String plainText = RSAEncryption.decrypt(cipherText, privateKey);
        return plainText;
    }
}
