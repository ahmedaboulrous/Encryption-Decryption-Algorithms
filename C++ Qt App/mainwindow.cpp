#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_pushButton_encrypt_clicked()
{
    QString plainText = ui->plainTextEdit_plain->toPlainText();
    QString encryptedText = "to be implemented";

    if(ui->comboBox->currentIndex() == 0)
    {
        int key = ui->lineEdit_CC_key->text().toInt();
        encryptedText = ewCaesarCipher(plainText, key);
    }
    else if(ui->comboBox->currentIndex() == 1)
    {
        QString secret = ui->lineEdit_PF_Secret->text();
        encryptedText = ewPlayfair(plainText, secret);
    }

    ui->plainTextEdit_encrypted->document()->setPlainText(encryptedText);
}

void MainWindow::on_pushButton_decrypt_clicked()
{
    QString decryptedText = ui->plainTextEdit_encrypted->toPlainText();
    QString plainText = "to be implemented";

    if(ui->comboBox->currentIndex() == 0)
    {
        int key = ui->lineEdit_CC_key->text().toInt();
        plainText = dwCaesarCipher(decryptedText, key);
    }
    else if(ui->comboBox->currentIndex() == 1)
    {
        QString secret = ui->lineEdit_PF_Secret->text();
        plainText = dwPlayfair(decryptedText, secret);
    }

    ui->plainTextEdit_plain->document()->setPlainText(plainText);
}

void MainWindow::on_actionReset_Fields_triggered()
{
    ui->plainTextEdit_plain->clear();
    ui->plainTextEdit_encrypted->clear();
    ui->lineEdit_CC_key->clear();
}

void MainWindow::on_actionClear_Plain_Text_triggered()
{
    ui->plainTextEdit_plain->clear();
}

void MainWindow::on_actionClear_Encrypted_Text_triggered()
{
    ui->plainTextEdit_encrypted->clear();
}

void MainWindow::on_actionExit_triggered()
{
    exit(0);
}

void MainWindow::on_actionAbout_Qt_triggered()
{
    QMessageBox::aboutQt(this);
}

void MainWindow::on_comboBox_currentTextChanged(const QString &arg1)
{
    if(arg1 == "Caesar Cipher")
    {
        ui->stackedWidget->setCurrentIndex(0);
    }
    else if(arg1 == "Playfair")
    {
        ui->stackedWidget->setCurrentIndex(1);
    }
}





// Caesar Cipher Methods

QString MainWindow::ewCaesarCipher(QString plainText, int key)
{
    std::string result = "";
    std::string plainStdText = plainText.toStdString();

    for (int i=0;i<plainText.length();i++)
    {
        if(plainStdText[i] == ' ')
        {
            result += ' ';
        }
        else if(std::isalpha(plainStdText[i]))
        {
            if (std::isupper(plainStdText[i]))
                result += char(int(plainStdText[i]+key-65)%26 +65);
            else
                result += char(int(plainStdText[i]+key-97)%26 +97);
        }
    }

    return QString::fromStdString(result);
}

QString MainWindow::dwCaesarCipher(QString encryptedText, int key)
{
    return ewCaesarCipher(encryptedText, 26-key);
}





// playfair Methods

QString MainWindow::ewPlayfair(QString plainText, QString secret)
{
    std::string plainStdText = plainText.toStdString();
    std::string secretStdText = secret.toStdString();

    normalizePFSecret(secretStdText);
    populatePFMatrix(secretStdText);
    normalizePFString(plainStdText);

    std::string encryptedText = encryptPFString(plainStdText);

    return QString::fromStdString(encryptedText);
}

QString MainWindow::dwPlayfair(QString encryptedText, QString secret)
{
    std::string encryptedStdText = encryptedText.toStdString();
    std::string secretStdText = secret.toStdString();

    normalizePFSecret(secretStdText);
    populatePFMatrix(secretStdText);

    std::string plainText = decryptPFString(encryptedStdText);

    return QString::fromStdString(plainText);
}

bool MainWindow::inSameRow(Position p1, Position p2)
{
    if(p1.x == p2.x)
        return true;
    return false;
}

bool MainWindow::inSameColumn(Position p1, Position p2)
{
    if(p1.y == p2.y)
        return true;
    return false;
}

void MainWindow::normalizePFString(std::string &str)
{
    std::string pure_str= "";
    // remove any non-alphabetical characters
    for(int i=0;i<str.size();++i)
    {
        if(isalpha(str[i]))
        {
            if(std::isupper(str[i]))
                str[i] = std::tolower(str[i]);
            pure_str += str[i];
        }
    }

    // separate duplicate characters
    for(int i=0 ; i<pure_str.size()-1 ; i+=2)
    {
        if(pure_str[i] == pure_str[i+1])
            pure_str.insert(pure_str.begin()+i+1, 'x');
    }

    // make string even
    if(pure_str.size()%2 !=0)
        pure_str += 'x';

    str = pure_str;
}

std::string MainWindow::encryptPFString(std::string plainStdText)
{
    std::string result = "";

    for(int i=0;i<plainStdText.size(); i+=2)
    {
        Position p1 = findPositionByChar(plainStdText[i]);
        Position p2 = findPositionByChar(plainStdText[i+1]);

        if(inSameRow(p1, p2))
        {
            if(p1.y == 4)
                p1.y = 0;
            else
                p1.y +=1;

            if(p2.y == 4)
                p2.y = 0;
            else
                p2.y +=1;

            result += findCharByPosition(p1);
            result += findCharByPosition(p2);
        }
        else if(inSameColumn(p1, p2))
        {
            if(p1.x == 4)
                p1.x = 0;
            else
                p1.x +=1;

            if(p2.x == 4)
                p2.x = 0;
            else
                p2.x +=1;

            result += findCharByPosition(p1);
            result += findCharByPosition(p2);
        }
        else
        {
            Position t1, t2;

            t1.x = p1.x;
            t1.y = p2.y;

            t2.x = p2.x;
            t2.y = p1.y;

            result += findCharByPosition(t1);
            result += findCharByPosition(t2);
        }
    }

    return result;
}

std::string MainWindow::decryptPFString(std::string encryptedStdText)
{
    std::string result = "";

    for(int i=0;i<encryptedStdText.size(); i+=2)
    {
        Position p1 = findPositionByChar(encryptedStdText[i]);
        Position p2 = findPositionByChar(encryptedStdText[i+1]);

        if(inSameRow(p1, p2))
        {
            if(p1.y == 0)
                p1.y = 4;
            else
                p1.y -=1;

            if(p2.y == 0)
                p2.y = 4;
            else
                p2.y -=1;

            result += findCharByPosition(p1);
            result += findCharByPosition(p2);
        }
        else if(inSameColumn(p1, p2))
        {
            if(p1.x == 0)
                p1.x = 4;
            else
                p1.x -=1;

            if(p2.x == 0)
                p2.x = 4;
            else
                p2.x -=1;

            result += findCharByPosition(p1);
            result += findCharByPosition(p2);
        }
        else
        {
            Position t1, t2;

            t1.x = p1.x;
            t1.y = p2.y;

            t2.x = p2.x;
            t2.y = p1.y;

            result += findCharByPosition(t1);
            result += findCharByPosition(t2);
        }
    }

    return result;
}

void MainWindow::normalizePFSecret(std::string &secret)
{
    std::string result = "";
    secret += "abcdefghiklmnopqrstuvwxyz";
    for(int i=0;i<secret.size();++i)
    {
        if(result.find(secret[i]) == std::string::npos)
            result += secret[i];
    }
    secret = result;
}

void MainWindow::populatePFMatrix(std::string secret)
{
    for(int i=0; i<5; ++i)
    {
        for(int j=0; j<5 ; ++j)
        {
            pfMatrix[i][j] = secret[j+5*i];
        }
    }
}

Position MainWindow::findPositionByChar(char ch)
{
    Position p;

    for(int i=0; i<5; ++i)
    {
        for(int j=0; j<5; ++j)
        {
            if(pfMatrix[i][j] == ch)
            {
                p.x = i;
                p.y = j;
            }
        }
    }

    return p;
}

char MainWindow::findCharByPosition(Position p)
{
    return pfMatrix[p.x][p.y];
}

