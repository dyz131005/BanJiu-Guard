// 最小插件测试：只验证平台插件静态导入是否导致崩溃
#include <QApplication>
#include <QLabel>
#include <QtPlugin>
Q_IMPORT_PLUGIN(QWindowsIntegrationPlugin)
Q_IMPORT_PLUGIN(QICOPlugin)
#include <cstdio>
#include <windows.h>

int main(int argc, char** argv)
{
    FILE* f = nullptr;
    fopen_s(&f, "D:\\Projects\\BanJiu-Guard\\BanJiu-Guard\\build\\diag_steps.txt", "w");
    auto log = [&](const char* s){ if(f){ fprintf(f, "%s\n", s); fflush(f);} };

    log("step1: main entered");
    QApplication app(argc, argv);
    log("step2: QApplication created");
    QLabel label("hello");
    label.resize(300,150);
    label.show();
    log("step3: label shown");
    int rc = app.exec();
    log("step4: app.exec returned");
    if(f) fclose(f);
    return rc;
}
