#include "mainwindow.h"
#include <QWidget>
#include <QVBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QProcess>
#include <QMessageBox>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
{
    setWindowTitle(tr("Mythware Toolkit"));
    QWidget *central = new QWidget(this);
    QVBoxLayout *layout = new QVBoxLayout(central);

    QLabel *title = new QLabel(tr("Mythware Toolkit"), this);
    title->setAlignment(Qt::AlignCenter);
    layout->addWidget(title);

    QPushButton *killMythware = new QPushButton(tr("Kill Mythware"), this);
    layout->addWidget(killMythware);

    QPushButton *killAssistant = new QPushButton(tr("Kill Assistant"), this);
    layout->addWidget(killAssistant);

    connect(killMythware, &QPushButton::clicked, this, [this]() {
#ifdef Q_OS_WIN
        QProcess::execute("taskkill", {"/f", "/im", "StudentMain.exe"});
        QMessageBox::information(this, tr("Done"), tr("StudentMain.exe terminated."));
#else
        QMessageBox::warning(this, tr("Unsupported"), tr("Available only on Windows."));
#endif
    });

    connect(killAssistant, &QPushButton::clicked, this, [this]() {
#ifdef Q_OS_WIN
        QProcess::execute("taskkill", {"/f", "/im", "Helper.exe"});
        QMessageBox::information(this, tr("Done"), tr("Helper.exe terminated."));
#else
        QMessageBox::warning(this, tr("Unsupported"), tr("Available only on Windows."));
#endif
    });

    setCentralWidget(central);
    resize(360, 200);
}
