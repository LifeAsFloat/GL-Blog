<div align="center">

# GL-Blog

![GL-Blog Logo](https://img.shields.io/badge/GL--Blog-1.0-blueviolet?style=for-the-badge&logo=blog)
[![Docker Image](https://img.shields.io/docker/v/lihupr/gl-blog?label=Docker%20Hub&style=for-the-badge&color=blue&logo=docker)](https://hub.docker.com/r/lihupr/gl-blog)
[![GitHub](https://img.shields.io/badge/GitHub-Lihu--PR-black?style=for-the-badge&logo=github)](https://github.com/Lihu-PR)
[![Go Language](https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go)](https://github.com/Lihu-PR)

**新一代极简轻量博客系统**  
专为个人博客和技术文档设计，无数据库依赖，支持一键部署和数据迁移。

<img width="2532" height="1333" alt="image" src="https://github.com/user-attachments/assets/90a058d9-7098-4383-adc9-271a18f238fc" />


*© 2025 GL-Blog • Designed for Simplicity*

</div>

---

## ✨ 核心特性

### 🎯 极致轻量设计

#### ⚡ 无数据库依赖
- 使用文件系统存储，零配置启动
- Markdown 文件存储文章内容
- JSON 文件管理元数据和配置
- 支持图片和附件本地存储

#### 💾 一键数据迁移
- 完整的数据导出功能（tar.gz 格式）
- 支持跨服务器无痛迁移
- 包含文章、图片、配置的完整备份
- 简单的导入恢复机制

#### 🔗 优雅的 URL 设计
- 无 `.html` 后缀，SEO 友好
- 简洁的路由结构
- 支持自定义文章链接

### 🔐 强大的管理系统

- **安全认证**：bcrypt 密码加密 + Session 会话管理
- **Markdown 编辑器**：集成 EasyMDE，支持实时预览
- **图片上传**：拖拽上传，自动处理文件存储
- **文章管理**：创建、编辑、删除文章
- **标签系统**：支持多标签分类管理
- **数据导出**：一键备份所有数据

### 🌐 全平台支持

- 📱 **响应式设计**：完美适配手机、平板和电脑
- 🐳 **Docker 部署**：支持 AMD64 架构一键部署
- ⚡ **高性能**：Go 语言编写，启动时间 < 100ms
- 🎨 **现代 UI**：毛玻璃效果，优雅的视觉设计
- 📝 **Markdown 全支持**：代码高亮、表格、链接等
- 🔄 **实时预览**：编辑时即时查看效果

---

## 📦 部署指南

> 💡 **推荐**：使用 Docker 部署是最快、最稳定的方式。

### 1️⃣ Docker 部署（推荐）

#### 🏠 快速启动
```bash
docker run -d \
  --name gl-blog \
  --restart unless-stopped \
  -p 3000:3000 \
  -v /path/to/data:/app/data \
  -e TZ=Asia/Shanghai \
  lihupr/gl-blog:latest
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
git clone <repository-url>
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
2. 按照引导创建管理员账号
3. 设置基本信息和社交链接
4. 开始创作您的第一篇文章

### 📝 文章管理
1. 访问管理后台：`http://localhost:3000/admin`
2. 使用 Markdown 编辑器创建文章
3. 支持拖拽上传图片和附件
4. 添加标签和分类进行组织
5. 实时预览确认效果后发布

### 💾 数据备份
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

**Q: 数据存储在哪里？**  
A: 所有数据存储在 `data/` 目录下：
- `data/posts/` - 文章 Markdown 文件
- `data/uploads/` - 上传的图片和附件  
- `data/metadata.json` - 配置和元数据

**Q: 忘记管理员密码怎么办？**  
A: 删除 `data/metadata.json` 中的 `admin` 字段，重新访问 `/setup` 设置新密码。

**Q: 如何更换服务器？**  
A: 
1. 在旧服务器：`./gl-blog -export`
2. 复制 `backup.tar.gz` 到新服务器
3. 在新服务器：`./gl-blog -import backup.tar.gz`
4. 启动服务

**Q: 支持多用户吗？**  
A: 支持用户注册和权限管理，管理员可以分配用户角色。

**Q: 可以自定义样式吗？**  
A: 可以！前台页面在 `public/` 目录，管理后台在 `admin/` 目录，支持完全自定义。

### 部署相关

**Q: Docker 容器无法启动？**  
A: 
```bash
# 查看日志
docker logs gl-blog

# 检查端口占用
netstat -tulpn | grep 3000

# 重新构建
docker-compose down
docker-compose up -d --build
```

**Q: 如何配置 Nginx 反向代理？**  
A: 
```nginx
server {
    listen 80;
    server_name your-domain.com;
    
    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

---

## 🚀 最新特性（v1.0）

### ✅ 核心功能
- **完整的博客系统**：文章创建、编辑、删除、展示
- **用户管理系统**：注册、登录、权限分配
- **引导设置**：首次使用自动引导配置
- **数据导出导入**：完整的备份恢复机制
- **移动端优化**：响应式设计，完美适配各种设备

### ✅ 界面优化
- **毛玻璃效果**：现代化的视觉设计
- **服务器状态监控**：实时显示 CPU、内存、负载
- **优雅动画**：流畅的交互体验
- **暗色主题**：护眼的夜间模式
- **代码高亮**：支持多种编程语言

### 📊 性能指标

| 指标 | 数值 |
|------|------|
| 二进制大小 | ~15 MB |
| 启动时间 | < 100ms |
| 内存占用 | ~20 MB |
| 响应时间 | < 5ms（本地） |
| 并发支持 | 数千连接 |

---

## 🛠️ 技术栈

- **后端**：Go 1.21+ + Gorilla Mux + Gorilla Sessions
- **前端**：原生 HTML/CSS/JavaScript + EasyMDE
- **存储**：文件系统（无数据库）
- **容器**：Docker + Docker Compose
- **安全**：bcrypt 密码加密 + Session 管理
- **设计**：响应式 + 毛玻璃效果

---

## 🔒 安全建议

1. ✅ 使用强密码（至少 12 位，包含字母数字符号）
2. ✅ 生产环境必须使用 HTTPS
3. ✅ 定期备份数据（使用 `-export` 命令）
4. ✅ 配置防火墙规则限制访问
5. ✅ 不要将 `data/` 目录提交到版本控制
6. ✅ 定期更新到最新版本

---

## 🤝 贡献与反馈

欢迎提交 Issue 或 PR 改进项目。

- **GitHub**：[Lihu-PR](https://github.com/Lihu-PR)
- **Docker Hub**：[lihupr](https://hub.docker.com/u/lihupr)
- **技术博客**：[lihu.site](https://lihu.site/)

---

## 📄 许可证

MIT License

---

<div align="center">

Made with ❤️ by Lihu-PR

**GL-Blog** - 让博客创作更简单、更优雅、更高效

</div>
