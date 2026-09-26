# Nexus Windows 客户端分发

正式下载页：https://yccwh2008.github.io/nexus-releases/

当前版本为 **0.1.1**。客户端在每位使用者自己的 Windows 64 位电脑运行，业务界面只监听本机；本站仅分发软件、安装说明和版本清单，不接收账号凭据、员工资料、任务数据库或业务产物。

## 安装

从下载页将 ZIP、对应 manifest 和 `install.ps1` 保存到同一文件夹，核对页面上的 SHA-256 后执行：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./install.ps1 -Zip ./Nexus-0.1.1.zip -Manifest ./Nexus-0.1.1.manifest.json
```

包内自带 Python，不需要安装开发环境。安装器创建桌面和登录启动入口；登录启动不主动打开浏览器。业务账号、模型配置和所需业务软件应在各自电脑配置，不复制其他电脑的数据库或 DPAPI 凭据。

## 更新

新版默认检查本站 `latest.json`，在本机 Nexus 提醒更新。下载并校验后，下次完整启动服务时切换版本；仅关闭网页窗口不等于停止后台服务。

0.1.0 保留作升级测试基线，常规新安装请选择当前版本。安装包包含可运行的 Python 程序文件，但不包含开发 Git 历史或运行时业务资料；开发 Git 仓库仍保持私有。

## 分发维护

发布通过手动 GitHub Actions 工作流完成，部署前核对各正式 Release 中规范资产的摘要、大小和历史版本保留情况。不得覆盖既有版本资产，也不能把发布站上线当作每台电脑或真实业务已经验收。