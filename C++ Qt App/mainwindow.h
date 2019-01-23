#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <string>
#include <cstring>
#include <cctype>
#include <QMessageBox>
#include <iostream>
#include <bitset>
#include <sstream>
#include <algorithm>

struct Position {
    int x;
    int y;
};

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

private slots:
    void on_pushButton_encrypt_clicked();
    void on_pushButton_decrypt_clicked();

    void on_actionReset_Fields_triggered();
    void on_actionClear_Plain_Text_triggered();
    void on_actionClear_Encrypted_Text_triggered();
    void on_actionExit_triggered();
    void on_actionAbout_Qt_triggered();

    void on_comboBox_currentTextChanged(const QString &arg1);

private:
    Ui::MainWindow *ui;
    QString ewCaesarCipher(QString plainText, int key);
    QString dwCaesarCipher(QString encryptedText, int key);

    QString ewPlayfair(QString plainText, QString secret);
    QString dwPlayfair(QString encryptedText, QString secret);

    char pfMatrix[5][5];
    bool inSameRow(Position p1, Position p2);
    bool inSameColumn(Position p1, Position p2);
    void normalizePFString(std::string &str);
    void normalizePFSecret(std::string &secret);
    void populatePFMatrix(std::string secret);
    std::string encryptPFString(std::string plainStdText);
    std::string decryptPFString(std::string encryptedStdText);
    Position findPositionByChar(char ch);
    char findCharByPosition(Position p);

    QString ewDES(QString plainText, std::string key);
    QString dwDES(QString encryptedText, std::string key);
    std::vector<std::string> keyPreparation(std::string key);
    QString DESEncryption(std::string dataBlock, std::vector< std::string > keys);
    std::string apply_xor(std::string str1, std::string str2);
    std::string apply_func_F(std::string str1, std::string str2);
    std::string apply_func_E(std::string str);

    QString ewIDES(QString plainText, std::string key);
    QString dwIDES(QString encryptedText, std::string key);
    std::vector< std::string > textToBinaryAscii(std::string str);
    std::string binaryAsciiToText(std::string str);
    std::string charToBinaryAscii(char ch);
    char binaryAsciiToChar(std::string binaryAscii);

    double ewRSA(double msg, double p, double q);
    double dwRSA(double msg, double p, double q);
    double RSAEncryption(double msg, double n, double e);
    double RSADecryption(double msg, double n, double d);
    std::pair<double, double> RSAKeys(double p, double q);
    int gcd(int a, int h);

    QString ewRC4(QString msg, QString key);
    QString dwRC4(QString msg, QString key);
    QString RC4Encryption(std::vector< std::bitset<8> > msg_bytes, std::vector< std::bitset<8> > keys);
    std::vector< std::bitset<8> > keysGenerator(int msg_length, std::vector<int> s);
    std::vector< std::bitset<8> > bytesOfMessage(std::string msg);

};



#endif // MAINWINDOW_H
