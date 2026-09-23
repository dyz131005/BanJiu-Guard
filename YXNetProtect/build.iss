; 脚本由 Inno Setup 脚本向导生成。
; 有关创建 Inno Setup 脚本文件的详细信息，请参阅帮助文档！
;
; 注：PrivilegesRequiredOverridesAllowed=dialog 会在安装开始时弹出"安装范围"对话框，
;     让用户选择：
;       · 为所有用户安装（需要管理员权限，默认选中 → 安装到 {pf}\BanJiu-Guard）
;       · 仅为当前用户安装（无需管理员 → 安装到 {userpf}\BanJiu-Guard，属于 AppData 目录树下）
;     无需再自己写 Pascal 代码实现切换。
;
;     DefaultDirName={autopf}\BanJiu-Guard 中的 {autopf} 会自动根据上述选择展开：
;       整机 → C:\Program Files\BanJiu-Guard
;       用户 → C:\Users\<你>\AppData\Local\Programs\BanJiu-Guard  （即 AppData 下面）

#define MyAppName "BanJiu-Guard"
#define MyAppVersion "1.0"
#define MyAppPublisher "dyz131005"
#define MyAppURL "https://space.bilibili.com/3546716410218699"
#define MyAppExeName "BanJiu-Guard.exe"

[Setup]
; 注意：AppId 的值唯一标识此应用程序。不要在其他应用程序的安装程序中使用相同的 AppId 值。
; (若要生成新的 GUID，请在 IDE 中单击 "工具|生成 GUID"。)
AppId={{B978460A-3B62-46B5-822B-F9FB504D1201}}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
;AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}

UninstallDisplayIcon={app}\{#MyAppExeName}
; "ArchitecturesAllowed=x64compatible" 指定安装程序无法运行
; 除 Arm 上的 x64 和 Windows 11 之外的任何平台上。
ArchitecturesAllowed=x64compatible
; "ArchitecturesInstallIn64BitMode=x64compatible" 要求
; 安装可以在 x64 或 Arm 上的 Windows 11 上以"64 位模式"完成，
; 这意味着它应该使用本机 64 位 Program Files 目录和
; 注册表的 64 位视图。
ArchitecturesInstallIn64BitMode=x64compatible
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
; 取消注释以下行以在非管理安装模式下运行 (仅为当前用户安装)。
;PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
OutputDir=dist
OutputBaseFilename=BanJiu-Guard安装程序
SetupIconFile=icon.ico
Compression=lzma2/ultra
SolidCompression=yes
WizardStyle=modern

[Tasks]
; —— 桌面快捷方式：默认不勾选
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
; —— 创建开始菜单文件夹：默认勾选（用户取消勾选 = 关闭创建）
Name: "startmenu";   Description: "创建开始菜单文件夹"; GroupDescription: "{cm:AdditionalIcons}"; Flags: checkedonce

[Files]
; 复制整个目录结构，保持原来的文件夹层次
; Kill.exe 和 Qt 插件 / 运行库 DLL 在同一级，保持目录结构不变
Source: "dist\BanJiu-Guard\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
; 注意：不要在任何共享系统文件上使用 "Flags: ignoreversion"

[Icons]
; 开始菜单文件夹（勾选了 startmenu 任务才会创建；用户取消勾选则完全不创建）
Name: "{group}\{#MyAppName}";                        Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\icon.ico"; Tasks: startmenu
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}";  Filename: "{uninstallexe}";                             Tasks: startmenu
; 桌面快捷方式
Name: "{autodesktop}\{#MyAppName}";                  Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\icon.ico"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent unchecked
