<div align="center">

# GL-Blog

![GL-Blog Logo](https://img.shields.io/badge/GL--Blog-1.0-blueviolet?style=for-the-badge&logo=blog)
[![Docker Image](https://img.shields.io/docker/v/lihupr/gl-blog?label=Docker%20Hub&style=for-the-badge&color=blue&logo=docker)](https://hub.docker.com/r/lihupr/gl-blog)
[![GitHub](https://img.shields.io/badge/GitHub-Lihu--PR-black?style=for-the-badge&logo=github)](https://github.com/Lihu-PR)
[![Go Language](https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go)](https://github.com/Lihu-PR)

**新一代极简轻量博客系统**  
基于 Go 语言开发的现代化个人博客平台，无数据库依赖，支持一键部署和数据迁移。  

  **[演示站点](https://blog.lihu-pr.top/)** - 仅作为演示站点，内容即项目默认内容
  
  **[方澄云](https://cloud.fcynet.com/aff/PFBBSXHP)** - 优质上游服务器供应商

<img width="2532" height="1333" alt="image" src="https://github.com/user-attachments/assets/90a058d9-7098-4383-adc9-271a18f238fc" />  
<img width="2516" height="1338" alt="image" src="https://github.com/user-attachments/assets/fac5d6b7-5850-4fc1-a556-9dfb225d6a0d" />



*© 2025 GL-Blog • Designed for Simplicity & Performance*

</div>

---

## ✨ 核心优势

### 🎯 Go 语言驱动的高性能架构

#### ⚡ 极致性能表现
- **启动速度**: < 100ms 闪电启动
- **内存占用**: 仅 ~20MB 运行内存
- **并发处理**: 支持数千并发连接
- **响应时间**: < 5ms 本地响应
- **二进制大小**: ~15MB 单文件部署

#### 🔧 零依赖设计
- **无数据库**: 使用文件系统存储，零配置启动
- **静态编译**: 单个二进制文件包含所有依赖
- **跨平台**: 支持 Linux/Windows/macOS
- **容器化**: 完美支持 Docker 部署

### 🌐 完美的移动端适配

#### 📱 响应式设计精髓
- **Apple 设计美学**: 参考大厂设计规范
- **毛玻璃效果**: 现代化视觉体验
- **流畅动画**: 60fps 丝滑交互
- **触控优化**: 完美的移动端操作体验
- **自适应布局**: 完美适配手机/平板/桌面

<img width="406" height="906" alt="image" src="https://github.com/user-attachments/assets/4d41fa11-23c4-46ba-9693-40150f9f729d" />

#### 🎨 现代化 UI 特性
- **动态背景**: 支持自定义背景图片
- **实时状态**: 服务器 CPU/内存/负载监控
- **优雅动效**: GSAP 驱动的流畅动画
- **暗色适配**: 护眼的夜间模式
- **代码高亮**: 支持多种编程语言

### 📧 企业级 SMTP 邮件系统

#### 🔐 完整的邮件功能
- **多协议支持**: SSL/STARTTLS/无加密
- **智能认证**: 支持密码和授权码
- **邮件验证**: 用户注册邮箱验证
- **登录提醒**: 异地登录安全通知
- **IP 定位**: 自动获取登录地理位置
- **批量发送**: 支持群发和模板邮件

<img width="2531" height="1332" alt="image" src="https://github.com/user-attachments/assets/0fdbd95a-ece7-47da-bd90-24a35f776619" />

#### 📮 邮件服务特性
- **主流邮箱**: 完美支持 Gmail/Outlook/QQ/163 等
- **自定义发件人**: 支持品牌化邮件显示
- **错误处理**: 详细的发送状态反馈
- **异步发送**: 不阻塞用户操作

### 👥 完善的用户管理系统

#### 🔑 多层级权限控制
- **站长权限**: 第一个注册用户自动成为站长
- **管理员角色**: 可管理内容和用户
- **普通用户**: 可注册、登录、评论
- **权限分配**: 灵活的角色管理

#### 🛡️ 安全认证机制
- **bcrypt 加密**: 工业级密码哈希
- **Session 管理**: 安全的会话控制
- **邮箱验证**: 防止恶意注册
- **登录监控**: 异常登录自动通知

---

## 🚀 技术特性

### 💾 智能数据管理

#### 📁 文件系统存储
- **Markdown 文件**: 文章内容存储为 .md 文件
- **JSON 元数据**: 结构化配置和索引
- **本地上传**: 图片和附件本地存储
- **版本控制**: 支持 Git 版本管理

#### 🔄 一键数据迁移
- **完整导出**: tar.gz 格式包含所有数据
- **跨服务器**: 无痛迁移到新服务器
- **增量备份**: 支持定期自动备份
- **快速恢复**: 一键导入恢复所有数据

### 🖥️ 实时系统监控

#### 📊 服务器状态监控
- **CPU 使用率**: 实时显示系统 CPU 占用
- **内存监控**: 准确的内存使用情况
- **负载均衡**: 系统负载平均值
- **系统信息**: 自动识别操作系统和架构
- **Docker 支持**: 容器内准确获取宿主机信息

#### 🔍 智能系统检测
- **操作系统**: 准确识别 Ubuntu/Debian/CentOS 等
- **架构检测**: 自动识别 AMD64/ARM64
- **容器环境**: 智能检测 Docker 运行环境
- **实时刷新**: 每 4 秒更新状态信息

### ✍️ 强大的内容管理

#### 📝 Markdown 编辑器
- **EasyMDE 集成**: 专业的 Markdown 编辑体验
- **实时预览**: 编辑时即时查看效果
- **语法高亮**: 支持代码语法着色
- **拖拽上传**: 图片直接拖拽插入
- **快捷键**: 丰富的编辑快捷键

<img width="2519" height="1335" alt="image" src="https://github.com/user-attachments/assets/fc17e1cf-8d2b-43e4-bbdf-1e24c8aabddc" />

#### 🏷️ 内容组织系统
- **分类管理**: 灵活的文章分类
- **标签系统**: 多标签文章组织
- **搜索功能**: 快速查找文章内容
- **归档展示**: 时间轴式文章归档

---

## 📦 部署指南

> 💡 **推荐**：使用 Docker 部署是最快、最稳定的方式。

### 1️⃣ Docker 部署（推荐）

#### 🏠 快速启动
```
docker run -d --name gl-blog --restart unless-stopped -p 3000:3000 -v /root/gl-blog/data:/app/data -e TZ=Asia/Shanghai lihupr/gl-blog:latest
```

#### 🛠️ 使用 Docker Compose
```yaml
version: '3.8'
services:
  gl-blog:
    image: lihupr/gl-blog:latest
    container_name: gl-blog
    restart: unless-stopped
    ports:
      - "3000:3000"
    volumes:
      - ./data:/app/data
    environment:
      - TZ=Asia/Shanghai
    healthcheck:
      test: ["CMD", "wget", "--quiet", "--tries=1", "--spider", "http://localhost:3000"]
      interval: 30s
      timeout: 10s
      retries: 3
```

> **访问地址**：打开浏览器访问 `http://服务器IP:3000`

---

### 2️⃣ 本地运行

#### ⚠️ 前置要求
- Go 1.21 或更高版本

#### 🛠️ 运行步骤

**Windows 用户（推荐）：**
```bash
# 双击运行
启动博客.bat

# 或命令行运行
gl-blog.exe
```

**Linux/Mac 用户：**
```bash
# 克隆项目
git clone https://github.com/Lihu-PR/GL-Blog.git
cd GL-Blog

# 安装依赖
go mod download

# 运行项目
go run .

# 或编译后运行
go build -o gl-blog
./gl-blog
```

**指定端口：**
```bash
./gl-blog -port 8080
```

---

## 🔧 使用说明

### 📤 首次使用
1. 启动服务器后访问 `http://localhost:3000/setup`
2. 按照引导创建管理员账号和设置基本信息
3. 配置 SMTP 邮件服务（可选）
4. 设置社交链接和个人信息
5. 开始创作您的第一篇文章

### 📝 内容管理
1. **文章创建**: 访问管理后台使用 Markdown 编辑器
2. **图片上传**: 支持拖拽上传和粘贴插入
3. **分类标签**: 灵活的内容组织方式
4. **实时预览**: 编辑时即时查看效果
5. **SEO 优化**: 自动生成友好的 URL

### 👥 用户管理
1. **用户注册**: 支持邮箱验证注册
2. **权限分配**: 管理员可分配用户角色
3. **登录监控**: 异地登录自动邮件通知
4. **安全设置**: 强密码策略和会话管理

### 💾 数据管理
```bash
# 导出所有数据
./gl-blog -export

# 导入数据（换服务器时使用）
./gl-blog -import backup.tar.gz
```

### 🐳 Docker 数据管理
```bash
# 导出数据
docker exec gl-blog ./gl-blog -export
docker cp gl-blog:/app/backup.tar.gz ./backup.tar.gz

# 导入数据
docker cp backup.tar.gz gl-blog:/app/backup.tar.gz
docker exec gl-blog ./gl-blog -import /app/backup.tar.gz
docker restart gl-blog
```

---

## ❓ 常见问题（FAQ）

### 基础问题

**Q: 为什么选择 Go 语言开发？**  
A: Go 语言具有以下优势：
- **高性能**: 编译型语言，执行效率高
- **并发处理**: 原生协程支持，轻松处理高并发
- **内存安全**: 垃圾回收机制，避免内存泄漏
- **跨平台**: 一次编译，到处运行
- **部署简单**: 静态编译，无需运行时依赖

**Q: 移动端体验如何？**  
A: GL-Blog 专门针对移动端进行了深度优化：
- **响应式设计**: 完美适配各种屏幕尺寸
- **触控优化**: 针对触屏操作优化的交互
- **加载速度**: 优化的资源加载和缓存策略
- **Apple 美学**: 参考 iOS 设计规范的界面风格

**Q: SMTP 邮件系统支持哪些功能？**  
A: 完整的企业级邮件功能：
- **用户验证**: 注册时邮箱验证
- **登录通知**: 异地登录安全提醒
- **密码重置**: 邮箱重置密码功能
- **多协议**: 支持 SSL/STARTTLS/无加密
- **主流邮箱**: Gmail/Outlook/QQ/163 等

**Q: 数据安全性如何保障？**  
A: 多重安全保障：
- **本地存储**: 数据完全在您的服务器上
- **加密存储**: bcrypt 加密用户密码
- **备份机制**: 支持完整数据导出备份
- **会话安全**: 安全的 Session 管理
- **权限控制**: 细粒度的用户权限管理

### 部署相关

**Q: 服务器配置要求？**  
A: 极低的硬件要求：
- **CPU**: 1 核心即可
- **内存**: 512MB 足够
- **存储**: 100MB 基础空间
- **网络**: 支持 HTTP/HTTPS 访问

**Q: 如何配置 HTTPS？**  
A: 推荐使用 Nginx 反向代理：
```nginx
server {
    listen 443 ssl http2;
    server_name your-domain.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

**Q: 如何进行性能优化？**  
A: 系统已内置多项优化：
- **静态文件**: 内嵌到二进制文件中
- **缓存策略**: 智能的浏览器缓存
- **压缩传输**: 自动 Gzip 压缩
- **并发处理**: Go 协程高效处理请求

---

## 🚀 最新特性（v1.0）

### ✅ 核心功能
- **完整博客系统**: 文章创建、编辑、删除、展示
- **用户管理**: 注册、登录、权限分配
- **邮件系统**: SMTP 配置、邮箱验证、登录通知
- **引导设置**: 首次使用自动引导配置
- **数据迁移**: 完整的备份恢复机制

### ✅ 界面优化
- **移动端适配**: 完美的响应式设计
- **毛玻璃效果**: 现代化的视觉设计
- **服务器监控**: 实时 CPU、内存、负载显示
- **优雅动画**: 流畅的交互体验
- **代码高亮**: 支持多种编程语言

### ✅ 性能提升
- **Go 语言**: 高性能后端架构
- **零数据库**: 文件系统存储，启动更快
- **静态编译**: 单文件部署，无依赖
- **容器优化**: Docker 镜像仅 ~12MB

---

## 🛠️ 技术栈

### 后端技术
- **语言**: Go 1.21+ (高性能、并发安全)
- **路由**: Gorilla Mux (灵活的 HTTP 路由)
- **会话**: Gorilla Sessions (安全的会话管理)
- **加密**: bcrypt (工业级密码哈希)
- **Markdown**: gomarkdown (高性能 Markdown 解析)
- **邮件**: net/smtp + crypto/tls (企业级邮件支持)

### 前端技术
- **编辑器**: EasyMDE (专业 Markdown 编辑)
- **动画**: GSAP (流畅的动画效果)
- **样式**: 原生 CSS3 (毛玻璃、响应式)
- **图标**: SVG (矢量图标系统)
- **字体**: Apple 系统字体栈

### 存储方案
- **文章**: Markdown 文件 (.md)
- **配置**: JSON 文件 (metadata.json)
- **上传**: 本地文件系统
- **备份**: tar.gz 压缩包

### 部署技术
- **容器**: Docker + Docker Compose
- **反向代理**: Nginx (推荐)
- **SSL**: Let's Encrypt (免费证书)
- **监控**: 内置系统状态监控

---

## 🔒 安全特性

### 🛡️ 数据安全
1. **本地存储**: 数据完全在您的服务器上
2. **加密存储**: bcrypt 哈希用户密码
3. **会话安全**: 安全的 Cookie 和 Session
4. **权限控制**: 细粒度的用户权限管理
5. **备份机制**: 完整数据导出和恢复

### 🔐 网络安全
1. **HTTPS 支持**: 支持 SSL/TLS 加密传输
2. **CSRF 防护**: 跨站请求伪造防护
3. **输入验证**: 严格的用户输入验证
4. **文件上传**: 安全的文件上传机制
5. **登录监控**: 异常登录自动通知

### 📧 邮件安全
1. **多协议**: SSL/STARTTLS/无加密支持
2. **认证机制**: 支持密码和授权码
3. **异步发送**: 不阻塞主要功能
4. **错误处理**: 详细的发送状态反馈
5. **IP 定位**: 登录地理位置追踪

---

## 🤝 贡献与反馈

欢迎提交 Issue 或 PR 改进项目。

- **GitHub**: [Lihu-PR](https://github.com/Lihu-PR)
- **Docker Hub**: [lihupr](https://hub.docker.com/u/lihupr)
- **技术博客**: [lihu.site](https://lihu.site/)

---

## 📄 许可证

MIT License - 详见 [LICENSE](LICENSE) 文件

---

<div align="center">

Made with ❤️ by Lihu-PR

**GL-Blog** - 让博客创作更简单、更优雅、更高效

*基于 Go 语言的现代化博客平台 • 完美移动端体验 • 企业级邮件系统*

</div>
