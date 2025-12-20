package main

import (
	"crypto/tls"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gomarkdown/markdown"
	"github.com/gomarkdown/markdown/html"
	"github.com/gomarkdown/markdown/parser"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
)

//go:embed public/*.html admin/*.html
var staticFiles embed.FS

var (
	store        = sessions.NewCookieStore([]byte("gl-blog-secret-key-change-this"))
	dataDir      = "data"
	postsDir     = filepath.Join(dataDir, "posts")
	uploadsDir   = filepath.Join(dataDir, "uploads")
	metadataFile = filepath.Join(dataDir, "metadata.json")
)

type Post struct {
	ID        string    `json:"id"`
	Title     string    `json:"title"`
	Slug      string    `json:"slug"`
	Date      time.Time `json:"date"`
	CreatedAt time.Time `json:"createdAt,omitempty"`
	UpdatedAt time.Time `json:"updatedAt,omitempty"`
	Category  string    `json:"category,omitempty"`
	Tags      []string  `json:"tags"`
	Excerpt   string    `json:"excerpt"`
	Cover     string    `json:"cover,omitempty"`
}

type SocialLink struct {
	Platform string `json:"platform"`
	URL      string `json:"url"`
	Icon     string `json:"icon"`
}

type Metadata struct {
	Posts             []Post                      `json:"posts"`
	Admin             *AdminConfig                `json:"admin,omitempty"`
	Users             []User                      `json:"users,omitempty"`
	SMTP              *SMTPConfig                 `json:"smtp,omitempty"`
	CustomBackground  string                      `json:"customBackground,omitempty"`
	SiteName          string                      `json:"siteName,omitempty"`
	GitHubURL         string                      `json:"githubUrl,omitempty"`
	EmailAddress      string                      `json:"emailAddress,omitempty"`
	Avatar            string                      `json:"avatar,omitempty"`
	Nickname          string                      `json:"nickname,omitempty"`
	Bio               string                      `json:"bio,omitempty"`
	SocialLinks       []SocialLink                `json:"socialLinks,omitempty"`
	Categories        []string                    `json:"categories,omitempty"`
	Tags              []string                    `json:"tags,omitempty"`
	Notice            string                      `json:"notice,omitempty"`
	SiteStartDate     string                      `json:"siteStartDate,omitempty"`
	VisitorCount      int                         `json:"visitorCount"`
	SetupCompleted    bool                        `json:"setupCompleted"`
	VerificationCodes map[string]VerificationCode `json:"verificationCodes,omitempty"`
	AboutTitle        string                      `json:"aboutTitle,omitempty"`
	AboutContent      string                      `json:"aboutContent,omitempty"`
}

type VerificationCode struct {
	Code      string    `json:"code"`
	Email     string    `json:"email"`
	ExpiresAt time.Time `json:"expiresAt"`
	Type      string    `json:"type"` // register or login
}

type AdminConfig struct {
	Username     string `json:"username"`
	PasswordHash string `json:"passwordHash"`
}

type User struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"passwordHash"`
	Nickname     string    `json:"nickname,omitempty"`
	Avatar       string    `json:"avatar,omitempty"`
	IsAdmin      bool      `json:"isAdmin"`
	CreatedAt    time.Time `json:"createdAt"`
	Verified     bool      `json:"verified"`
}

type SMTPConfig struct {
	Server      string `json:"server"`
	Port        int    `json:"port"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	DisplayName string `json:"displayName"`
	Encryption  string `json:"encryption"` // SSL, TLS, or NONE
}

type CreatePostRequest struct {
	Title    string   `json:"title"`
	Content  string   `json:"content"`
	Category string   `json:"category"`
	Tags     []string `json:"tags"`
	Cover    string   `json:"cover"`
}

func main() {
	// 命令行参数
	exportCmd := flag.Bool("export", false, "导出所有数据")
	importCmd := flag.String("import", "", "导入数据文件路径")
	port := flag.String("port", "3000", "服务器端口")
	flag.Parse()

	// 初始化数据目录
	if err := initDirectories(); err != nil {
		log.Fatal("初始化目录失败:", err)
	}

	// 处理导出命令
	if *exportCmd {
		if err := exportData(); err != nil {
			log.Fatal("导出失败:", err)
		}
		fmt.Println("数据导出成功: backup.tar.gz")
		return
	}

	// 处理导入命令
	if *importCmd != "" {
		if err := importData(*importCmd); err != nil {
			log.Fatal("导入失败:", err)
		}
		fmt.Println("数据导入成功")
		return
	}

	// 启动 Web 服务器
	r := mux.NewRouter()

	// API 路由
	api := r.PathPrefix("/api").Subrouter()
	api.HandleFunc("/posts", getPosts).Methods("GET")
	api.HandleFunc("/post/{slug}", getPost).Methods("GET")
	api.HandleFunc("/login", login).Methods("POST")
	api.HandleFunc("/logout", logout).Methods("POST")
	api.HandleFunc("/posts", requireAuth(createPost)).Methods("POST")
	api.HandleFunc("/posts/{id}", requireAuth(updatePost)).Methods("PUT")
	api.HandleFunc("/posts/{id}", requireAuth(deletePost)).Methods("DELETE")
	api.HandleFunc("/upload", requireAuth(uploadFile)).Methods("POST")
	api.HandleFunc("/files", requireAuth(listFiles)).Methods("GET")
	api.HandleFunc("/files/{filename}", requireAuth(deleteFile)).Methods("DELETE")
	api.HandleFunc("/export-data", requireAuth(exportDataAPI)).Methods("GET")
	api.HandleFunc("/import-data", requireAuth(importDataAPI)).Methods("POST")
	api.HandleFunc("/upload-background", requireAuth(uploadBackground)).Methods("POST")
	api.HandleFunc("/reset-background", requireAuth(resetBackground)).Methods("POST")
	api.HandleFunc("/settings", getSettings).Methods("GET")
	api.HandleFunc("/settings", requireAuth(updateSettings)).Methods("POST")
	api.HandleFunc("/setup", setupSite).Methods("POST")
	api.HandleFunc("/user-register", userRegister).Methods("POST")
	api.HandleFunc("/user-login", userLogin).Methods("POST")
	api.HandleFunc("/user-info", requireUserAuth(getUserInfo)).Methods("GET")
	api.HandleFunc("/user-profile", requireUserAuth(updateUserProfile)).Methods("PUT")
	api.HandleFunc("/users", requireAuth(getAllUsers)).Methods("GET")
	api.HandleFunc("/user-role", requireAuth(updateUserRole)).Methods("POST")
	api.HandleFunc("/users/{id}", requireAuth(deleteUser)).Methods("DELETE")
	api.HandleFunc("/send-verification-code", sendVerificationCode).Methods("POST")
	api.HandleFunc("/smtp-config", requireAuth(getSMTPConfig)).Methods("GET")
	api.HandleFunc("/smtp-config", requireAuth(updateSMTPConfig)).Methods("POST")
	api.HandleFunc("/test-smtp", requireAuth(testSMTP)).Methods("POST")
	api.HandleFunc("/check-setup", checkSetupStatus).Methods("GET")
	api.HandleFunc("/debug-metadata", debugMetadata).Methods("GET")
	api.HandleFunc("/about", getAbout).Methods("GET")
	api.HandleFunc("/about", requireAuth(updateAbout)).Methods("POST")
	api.HandleFunc("/about-page", getAbout).Methods("GET")
	api.HandleFunc("/about-page", requireAuth(updateAbout)).Methods("POST")
	api.HandleFunc("/server-status", getServerStatus).Methods("GET")
	api.HandleFunc("/reset-site", requireAuth(resetSite)).Methods("POST")
	api.HandleFunc("/change-password", requireUserAuth(changePassword)).Methods("POST")
	api.HandleFunc("/reset-password", resetPassword).Methods("POST")
	api.HandleFunc("/change-email", requireAuth(changeEmail)).Methods("POST")

	// 静态文件
	r.PathPrefix("/uploads/").Handler(http.StripPrefix("/uploads/", http.FileServer(http.Dir(uploadsDir))))
	r.PathPrefix("/BG/").Handler(http.StripPrefix("/BG/", http.FileServer(http.Dir("BG"))))

	// 前台页面
	r.HandleFunc("/", checkSetup(trackVisitor(servePage("public/index.html")))).Methods("GET")
	r.HandleFunc("/post/{slug}", checkSetup(servePage("public/post.html"))).Methods("GET")
	r.HandleFunc("/archive", checkSetup(servePage("public/archive.html"))).Methods("GET")
	r.HandleFunc("/about", checkSetup(servePage("public/about.html"))).Methods("GET")
	r.HandleFunc("/login", checkSetup(servePage("public/login.html"))).Methods("GET")
	r.HandleFunc("/reset-password", checkSetup(servePage("public/reset-password.html"))).Methods("GET")
	r.HandleFunc("/profile", checkSetup(servePage("public/profile.html"))).Methods("GET")
	r.HandleFunc("/admin", checkSetup(requireAuth(servePage("admin/posts.html")))).Methods("GET")
	r.HandleFunc("/admin/posts", checkSetup(requireAuth(servePage("admin/posts.html")))).Methods("GET")
	r.HandleFunc("/admin/files", checkSetup(requireAuth(servePage("admin/files.html")))).Methods("GET")
	r.HandleFunc("/admin/settings", checkSetup(requireAuth(servePage("admin/settings.html")))).Methods("GET")
	r.HandleFunc("/setup", blockSetupIfCompleted(servePage("public/setup.html"))).Methods("GET")

	// 静态资源
	r.PathPrefix("/public/").Handler(http.FileServer(http.FS(staticFiles)))
	r.PathPrefix("/admin/").Handler(checkSetupMiddleware(http.FileServer(http.FS(staticFiles))))

	addr := ":" + *port
	fmt.Printf("🚀 博客服务器启动成功！\n")
	fmt.Printf("📝 前台地址: http://localhost:%s\n", *port)
	fmt.Printf("⚙️  管理后台: http://localhost:%s/admin\n", *port)
	fmt.Printf("💾 数据目录: %s\n\n", dataDir)

	log.Fatal(http.ListenAndServe(addr, r))
}

func initDirectories() error {
	dirs := []string{dataDir, postsDir, uploadsDir}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}

	// 初始化 metadata.json
	if _, err := os.Stat(metadataFile); os.IsNotExist(err) {
		metadata := Metadata{Posts: []Post{}}
		return saveMetadata(&metadata)
	}
	return nil
}

func loadMetadata() (*Metadata, error) {
	data, err := os.ReadFile(metadataFile)
	if err != nil {
		return nil, err
	}

	var metadata Metadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, err
	}
	return &metadata, nil
}

func saveMetadata(metadata *Metadata) error {
	data, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(metadataFile, data, 0644)
}

func slugify(title string) string {
	slug := strings.ToLower(title)
	slug = strings.ReplaceAll(slug, " ", "-")
	// 简单的中文处理：保留中文字符
	var result strings.Builder
	for _, r := range slug {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r >= 0x4e00 && r <= 0x9fff {
			result.WriteRune(r)
		}
	}
	return result.String()
}

func servePage(path string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		content, err := staticFiles.ReadFile(path)
		if err != nil {
			http.Error(w, "页面不存在", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(content)
	}
}

// API Handlers

func getPosts(w http.ResponseWriter, r *http.Request) {
	metadata, err := loadMetadata()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 按日期排序
	posts := metadata.Posts
	sort.Slice(posts, func(i, j int) bool {
		return posts[i].Date.After(posts[j].Date)
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(posts)
}

func getPost(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	slug := vars["slug"]

	metadata, err := loadMetadata()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var post *Post
	for _, p := range metadata.Posts {
		if p.Slug == slug {
			post = &p
			break
		}
	}

	if post == nil {
		http.Error(w, "文章不存在", http.StatusNotFound)
		return
	}

	// 读取文章内容
	content, err := os.ReadFile(filepath.Join(postsDir, post.ID+".md"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"id":        post.ID,
		"title":     post.Title,
		"slug":      post.Slug,
		"date":      post.Date,
		"updatedAt": post.UpdatedAt,
		"tags":      post.Tags,
		"excerpt":   post.Excerpt,
		"content":   string(content),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	metadata, err := loadMetadata()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 首次登录设置密码
	if metadata.Admin == nil {
		hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		metadata.Admin = &AdminConfig{PasswordHash: string(hash)}
		if err := saveMetadata(metadata); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		session, _ := store.Get(r, "session")
		session.Values["admin"] = true
		session.Save(r, w)

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":   true,
			"firstTime": true,
		})
		return
	}

	// 验证密码
	if err := bcrypt.CompareHashAndPassword([]byte(metadata.Admin.PasswordHash), []byte(req.Password)); err != nil {
		http.Error(w, "密码错误", http.StatusUnauthorized)
		return
	}

	session, _ := store.Get(r, "session")
	session.Values["admin"] = true
	session.Save(r, w)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

func logout(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	session.Values["admin"] = false
	session.Options.MaxAge = -1
	session.Save(r, w)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

func createPost(w http.ResponseWriter, r *http.Request) {
	var req CreatePostRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	metadata, err := loadMetadata()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	now := time.Now()
	post := Post{
		ID:        strconv.FormatInt(now.UnixNano(), 10),
		Title:     req.Title,
		Slug:      slugify(req.Title),
		Date:      now,
		CreatedAt: now,
		Category:  req.Category,
		Tags:      req.Tags,
		Excerpt:   getExcerpt(req.Content, 150),
		Cover:     req.Cover,
	}

	// 保存文章内容
	if err := os.WriteFile(filepath.Join(postsDir, post.ID+".md"), []byte(req.Content), 0644); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	metadata.Posts = append(metadata.Posts, post)
	if err := saveMetadata(metadata); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(post)
}

func updatePost(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	var req CreatePostRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	metadata, err := loadMetadata()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	found := false
	for i, p := range metadata.Posts {
		if p.ID == id {
			metadata.Posts[i].Title = req.Title
			metadata.Posts[i].Slug = slugify(req.Title)
			metadata.Posts[i].Category = req.Category
			metadata.Posts[i].Tags = req.Tags
			metadata.Posts[i].Excerpt = getExcerpt(req.Content, 150)
			metadata.Posts[i].Cover = req.Cover
			metadata.Posts[i].UpdatedAt = time.Now()
			found = true
			break
		}
	}

	if !found {
		http.Error(w, "文章不存在", http.StatusNotFound)
		return
	}

	if err := os.WriteFile(filepath.Join(postsDir, id+".md"), []byte(req.Content), 0644); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := saveMetadata(metadata); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func deletePost(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	metadata, err := loadMetadata()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	newPosts := []Post{}
	for _, p := range metadata.Posts {
		if p.ID != id {
			newPosts = append(newPosts, p)
		}
	}
	metadata.Posts = newPosts

	os.Remove(filepath.Join(postsDir, id+".md"))

	if err := saveMetadata(metadata); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func uploadFile(w http.ResponseWriter, r *http.Request) {
	r.ParseMultipartForm(10 << 20) // 10 MB

	file, handler, err := r.FormFile("file")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()

	filename := fmt.Sprintf("%d-%s", time.Now().UnixNano(), handler.Filename)
	filepath := filepath.Join(uploadsDir, filename)

	dst, err := os.Create(filepath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer dst.Close()

	if _, err := io.Copy(dst, file); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"url":      "/uploads/" + filename,
		"filename": handler.Filename,
	})
}

func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "session")
		if auth, ok := session.Values["admin"].(bool); !ok || !auth {
			http.Error(w, "未授权", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func requireUserAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "session")
		if userID, ok := session.Values["userID"].(string); !ok || userID == "" {
			http.Error(w, "未授权", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func getExcerpt(content string, length int) string {
	// 移除 Markdown 标记
	extensions := parser.CommonExtensions | parser.AutoHeadingIDs
	p := parser.NewWithExtensions(extensions)
	doc := p.Parse([]byte(content))

	htmlFlags := html.CommonFlags | html.HrefTargetBlank
	opts := html.RendererOptions{Flags: htmlFlags}
	renderer := html.NewRenderer(opts)

	html := markdown.Render(doc, renderer)
	text := string(html)

	// 简单去除 HTML 标签
	text = strings.ReplaceAll(text, "<p>", "")
	text = strings.ReplaceAll(text, "</p>", " ")
	text = strings.ReplaceAll(text, "<br>", " ")

	runes := []rune(text)
	if len(runes) > length {
		return string(runes[:length]) + "..."
	}
	return string(runes)
}

func uploadBackground(w http.ResponseWriter, r *http.Request) {
	r.ParseMultipartForm(10 << 20) // 10 MB

	file, handler, err := r.FormFile("background")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()

	// 检查是否是图片
	if !strings.HasPrefix(handler.Header.Get("Content-Type"), "image/") {
		http.Error(w, "只能上传图片文件", http.StatusBadRequest)
		return
	}

	filename := fmt.Sprintf("custom-bg-%d%s", time.Now().UnixNano(), filepath.Ext(handler.Filename))
	filepath := filepath.Join(uploadsDir, filename)

	dst, err := os.Create(filepath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer dst.Close()

	if _, err := io.Copy(dst, file); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 更新元数据
	metadata, err := loadMetadata()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	metadata.CustomBackground = "/uploads/" + filename
	if err := saveMetadata(metadata); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"url": "/uploads/" + filename,
	})
}

func resetBackground(w http.ResponseWriter, r *http.Request) {
	metadata, err := loadMetadata()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	metadata.CustomBackground = ""
	if err := saveMetadata(metadata); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

func resetSite(w http.ResponseWriter, r *http.Request) {
	// 删除所有文章
	files, err := os.ReadDir(postsDir)
	if err == nil {
		for _, file := range files {
			if !file.IsDir() {
				os.Remove(filepath.Join(postsDir, file.Name()))
			}
		}
	}

	// 删除所有上传文件
	files, err = os.ReadDir(uploadsDir)
	if err == nil {
		for _, file := range files {
			if !file.IsDir() {
				os.Remove(filepath.Join(uploadsDir, file.Name()))
			}
		}
	}

	// 创建默认的metadata
	defaultMetadata := &Metadata{
		SiteName:       "GL-Blog",
		SetupCompleted: false,
		SiteStartDate:  time.Now().Format("2006-01-02"),
		Posts: []Post{
			{
				ID:        fmt.Sprintf("%d", time.Now().UnixNano()),
				Title:     "欢迎使用 GL-Blog",
				Slug:      "welcome-to-gl-blog",
				Date:      time.Now().Add(-2 * time.Hour),
				CreatedAt: time.Now().Add(-2 * time.Hour),
				UpdatedAt: time.Now().Add(-2 * time.Hour),
				Category:  "技术",
				Tags:      []string{"Go", "前端"},
				Excerpt:   "欢迎使用 GL-Blog，这是一个极简、优雅的个人博客系统。本文介绍了主要特性和使用方法。",
				Cover:     "/BG/BG.png",
			},
			{
				ID:        fmt.Sprintf("%d", time.Now().UnixNano()+1),
				Title:     "Docker 容器化部署指南",
				Slug:      "docker-deployment-guide",
				Date:      time.Now().Add(-1 * time.Hour),
				CreatedAt: time.Now().Add(-1 * time.Hour),
				UpdatedAt: time.Now().Add(-1 * time.Hour),
				Category:  "技术",
				Tags:      []string{"Docker", "后端"},
				Excerpt:   "详细介绍如何使用 Docker 容器化部署 GL-Blog 博客系统，包括镜像构建、容器运行和数据持久化。",
				Cover:     "/BG/BG.png",
			},
			{
				ID:        fmt.Sprintf("%d", time.Now().UnixNano()+2),
				Title:     "我的编程学习心得",
				Slug:      "my-programming-learning-experience",
				Date:      time.Now().Add(-30 * time.Minute),
				CreatedAt: time.Now().Add(-30 * time.Minute),
				UpdatedAt: time.Now().Add(-30 * time.Minute),
				Category:  "随笔",
				Tags:      []string{"Go", "前端", "后端"},
				Excerpt:   "分享个人编程学习的心得体会，包括学习方法、技术栈选择和一些感悟思考。",
				Cover:     "/BG/BG.png",
			},
		},
		Admin: nil,
		SocialLinks: []SocialLink{
			{Platform: "GitHub", URL: "https://github.com/Lihu-PR", Icon: "github"},
			{Platform: "Bilibili", URL: "https://space.bilibili.com/305674742", Icon: "bilibili"},
			{Platform: "Email", URL: "mailto:17192413622@163.com", Icon: "email"},
			{Platform: "Douyin", URL: "https://www.douyin.com/user/MS4wLjABAAAAEpo7zO7BLFarRWgMsew-oyw2WeDmgaNL-bjeVFEusNU?from_tab_name=main", Icon: "douyin"},
		},
		Nickname:     "Lihu-PR",
		Bio:          "Be water my friend",
		Avatar:       "/BG/icon.jpg",
		Notice:       "欢迎来到我的博客！",
		Categories:   []string{"技术", "生活", "随笔"},
		Tags:         []string{"Go", "前端", "后端", "Docker"},
		VisitorCount: 0,
		Users:        []User{},
		AboutTitle:   "关于本站",
		AboutContent: "# 欢迎来到 GL-Blog\n\n这是一个极简、优雅的个人博客系统。\n\n## 关于博主\n\n我是 Lihu-PR，一名热爱技术的开发者。\n\n**Be water my friend**",
	}

	if err := saveMetadata(defaultMetadata); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 创建示例文章的内容文件
	sampleContents := map[string]string{
		"welcome-to-gl-blog":                 "# 欢迎使用 GL-Blog\n\n这是您的第一篇示例文章！GL-Blog 是一个极简、优雅的个人博客系统。\n\n## 主要特性\n\n- 🎨 现代化的界面设计\n- 📱 完美的响应式布局\n- ✍️ Markdown 编辑支持\n- 🏷️ 分类和标签管理\n- 📊 访问统计功能\n- 🔐 用户权限管理\n\n开始您的博客之旅吧！",
		"docker-deployment-guide":            "# Docker 容器化部署指南\n\n本文将介绍如何使用 Docker 部署 GL-Blog 博客系统。\n\n## 准备工作\n\n首先确保您的系统已安装 Docker：\n\n```bash\ndocker --version\n```\n\n## 构建镜像\n\n```bash\ndocker build -t gl-blog .\n```\n\n## 运行容器\n\n```bash\ndocker run -d -p 3000:3000 --name gl-blog gl-blog\n```\n\n## 数据持久化\n\n为了保证数据不丢失，建议挂载数据目录：\n\n```bash\ndocker run -d -p 3000:3000 -v ./data:/app/data --name gl-blog gl-blog\n```\n\n这样就完成了 Docker 部署！",
		"my-programming-learning-experience": "# 我的编程学习心得\n\n回顾这些年的编程学习历程，有很多感悟想要分享。\n\n## 学习方法\n\n### 1. 理论与实践并重\n\n不能只看书不动手，也不能只写代码不思考。理论指导实践，实践验证理论。\n\n### 2. 建立知识体系\n\n- 从基础开始，循序渐进\n- 注重知识点之间的联系\n- 定期回顾和总结\n\n### 3. 保持好奇心\n\n技术日新月异，保持学习的热情和好奇心很重要。\n\n## 技术栈选择\n\n目前主要专注于：\n- **后端**: Go, Node.js\n- **前端**: React, Vue\n- **数据库**: MySQL, Redis\n- **运维**: Docker, Kubernetes\n\n## 总结\n\n编程是一个持续学习的过程，享受这个过程比结果更重要。\n\n**Be water my friend** - 像水一样，适应环境，持续流动。",
	}

	// 为每篇示例文章创建内容文件
	for _, post := range defaultMetadata.Posts {
		if content, exists := sampleContents[post.Slug]; exists {
			if err := os.WriteFile(filepath.Join(postsDir, post.ID+".md"), []byte(content), 0644); err != nil {
				log.Printf("创建示例文章内容失败: %v", err)
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

func changePassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email       string `json:"email"`
		Code        string `json:"code"`
		NewPassword string `json:"newPassword"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "无效的请求", http.StatusBadRequest)
		return
	}

	metadata, err := loadMetadata()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 验证验证码
	if metadata.VerificationCodes == nil {
		http.Error(w, "验证码不存在或已过期", http.StatusBadRequest)
		return
	}

	vc, exists := metadata.VerificationCodes[req.Email]
	if !exists || vc.Code != req.Code || time.Now().After(vc.ExpiresAt) {
		http.Error(w, "验证码无效或已过期", http.StatusBadRequest)
		return
	}

	// 查找用户并更新密码
	found := false
	for i := range metadata.Users {
		if metadata.Users[i].Email == req.Email {
			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			metadata.Users[i].PasswordHash = string(hashedPassword)
			found = true
			break
		}
	}

	if !found {
		http.Error(w, "用户不存在", http.StatusNotFound)
		return
	}

	// 删除已使用的验证码
	delete(metadata.VerificationCodes, req.Email)

	if err := saveMetadata(metadata); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 发送密码修改成功通知邮件
	if metadata.SMTP != nil {
		clientIP := r.RemoteAddr
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			clientIP = forwarded
		}

		location := getIPGeolocation(clientIP)
		subject := "您的密码已修改成功"
		body := fmt.Sprintf(`您好！

您的账户密码已成功修改。

修改时间：%s
修改IP：%s
IP归属地：%s

如果这不是您的操作，请立即联系管理员！`,
			time.Now().Format("2006-01-02 15:04:05"),
			clientIP,
			location)

		sendEmail(metadata.SMTP, req.Email, subject, body)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

func changeEmail(w http.ResponseWriter, r *http.Request) {
	var req struct {
		NewEmail string `json:"newEmail"`
		Code     string `json:"code"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "无效的请求", http.StatusBadRequest)
		return
	}

	// 从session获取当前用户
	session, _ := store.Get(r, "session")
	userID, ok := session.Values["userID"].(string)
	if !ok {
		http.Error(w, "未登录", http.StatusUnauthorized)
		return
	}

	metadata, err := loadMetadata()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 验证验证码
	if metadata.VerificationCodes == nil {
		http.Error(w, "验证码不存在或已过期", http.StatusBadRequest)
		return
	}

	vc, exists := metadata.VerificationCodes[req.NewEmail]
	if !exists || vc.Code != req.Code || time.Now().After(vc.ExpiresAt) {
		http.Error(w, "验证码无效或已过期", http.StatusBadRequest)
		return
	}

	// 查找当前用户并更新邮箱
	var oldEmail string
	found := false
	for i := range metadata.Users {
		if metadata.Users[i].ID == userID {
			oldEmail = metadata.Users[i].Email
			metadata.Users[i].Email = req.NewEmail
			found = true
			break
		}
	}

	if !found {
		http.Error(w, "用户不存在", http.StatusNotFound)
		return
	}

	// 删除已使用的验证码
	delete(metadata.VerificationCodes, req.NewEmail)

	if err := saveMetadata(metadata); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 发送换绑成功通知邮件到旧邮箱
	if metadata.SMTP != nil && oldEmail != "" {
		clientIP := r.RemoteAddr
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			clientIP = forwarded
		}

		location := getIPGeolocation(clientIP)
		subject := "您的账号邮箱已换绑"
		body := fmt.Sprintf(`您好！

您的账户邮箱已成功换绑。

换绑时间：%s
换绑IP：%s
IP归属地：%s
新邮箱：%s

如果这不是您的操作，请立即联系管理员！`,
			time.Now().Format("2006-01-02 15:04:05"),
			clientIP,
			location,
			req.NewEmail)

		sendEmail(metadata.SMTP, oldEmail, subject, body)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

func resetPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email       string `json:"email"`
		Code        string `json:"code"`
		NewPassword string `json:"newPassword"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "无效的请求", http.StatusBadRequest)
		return
	}

	metadata, err := loadMetadata()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 验证验证码
	if metadata.VerificationCodes == nil {
		http.Error(w, "验证码不存在或已过期", http.StatusBadRequest)
		return
	}

	vc, exists := metadata.VerificationCodes[req.Email]
	if !exists || vc.Code != req.Code || time.Now().After(vc.ExpiresAt) {
		http.Error(w, "验证码无效或已过期", http.StatusBadRequest)
		return
	}

	// 查找用户并更新密码
	found := false
	for i := range metadata.Users {
		if metadata.Users[i].Email == req.Email {
			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			metadata.Users[i].PasswordHash = string(hashedPassword)
			found = true
			break
		}
	}

	if !found {
		http.Error(w, "用户不存在", http.StatusNotFound)
		return
	}

	// 删除已使用的验证码
	delete(metadata.VerificationCodes, req.Email)

	if err := saveMetadata(metadata); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 发送密码修改成功通知邮件
	if metadata.SMTP != nil {
		clientIP := r.RemoteAddr
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			clientIP = forwarded
		}

		location := getIPGeolocation(clientIP)
		subject := "您的密码已修改成功"
		body := fmt.Sprintf(`您好！

您的账户密码已成功修改（找回密码）。

修改时间：%s
修改IP：%s
IP归属地：%s

如果这不是您的操作，请立即联系管理员！`,
			time.Now().Format("2006-01-02 15:04:05"),
			clientIP,
			location)

		sendEmail(metadata.SMTP, req.Email, subject, body)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

func getSettings(w http.ResponseWriter, r *http.Request) {
	metadata, err := loadMetadata()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metadata)
}

type UpdateSettingsRequest struct {
	SiteName      string       `json:"siteName"`
	GitHubURL     string       `json:"githubUrl"`
	EmailAddress  string       `json:"emailAddress"`
	Avatar        string       `json:"avatar"`
	Nickname      string       `json:"nickname"`
	Bio           string       `json:"bio"`
	SocialLinks   []SocialLink `json:"socialLinks"`
	Categories    []string     `json:"categories"`
	Tags          []string     `json:"tags"`
	Notice        string       `json:"notice"`
	SiteStartDate string       `json:"siteStartDate"`
}

func updateSettings(w http.ResponseWriter, r *http.Request) {
	var req UpdateSettingsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	metadata, err := loadMetadata()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	metadata.SiteName = req.SiteName
	metadata.GitHubURL = req.GitHubURL
	metadata.EmailAddress = req.EmailAddress
	metadata.Avatar = req.Avatar
	metadata.Nickname = req.Nickname
	metadata.Bio = req.Bio
	metadata.SocialLinks = req.SocialLinks
	metadata.Categories = req.Categories
	metadata.Tags = req.Tags
	metadata.Notice = req.Notice
	metadata.SiteStartDate = req.SiteStartDate

	if err := saveMetadata(metadata); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

func checkSetup(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		metadata, err := loadMetadata()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// 如果未完成设置，重定向到设置页面
		if !metadata.SetupCompleted {
			http.Redirect(w, r, "/setup", http.StatusTemporaryRedirect)
			return
		}

		next(w, r)
	}
}

func checkSetupMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		metadata, err := loadMetadata()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// 如果未完成设置，重定向到设置页面
		if !metadata.SetupCompleted {
			http.Redirect(w, r, "/setup", http.StatusTemporaryRedirect)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func blockSetupIfCompleted(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		metadata, err := loadMetadata()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// 如果已经完成设置，重定向到首页
		if metadata.SetupCompleted {
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}

		next(w, r)
	}
}

func trackVisitor(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 简单的访客统计（每次访问首页+1）
		metadata, err := loadMetadata()
		if err == nil {
			metadata.VisitorCount++
			saveMetadata(metadata)
		}
		next(w, r)
	}
}

func checkSetupStatus(w http.ResponseWriter, r *http.Request) {
	metadata, err := loadMetadata()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"setupCompleted": metadata.SetupCompleted,
		"siteName":       metadata.SiteName,
	})
}

func debugMetadata(w http.ResponseWriter, r *http.Request) {
	metadata, err := loadMetadata()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":              err.Error(),
			"metadataFileExists": false,
		})
		return
	}

	// 检查metadata.json文件是否存在
	_, fileErr := os.Stat(metadataFile)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"setupCompleted":     metadata.SetupCompleted,
		"siteName":           metadata.SiteName,
		"adminUsername":      metadata.Admin.Username,
		"metadataFileExists": fileErr == nil,
		"metadataFilePath":   metadataFile,
		"hasUsers":           len(metadata.Users) > 0,
		"userCount":          len(metadata.Users),
	})
}

type SetupRequest struct {
	SiteName string `json:"siteName"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

func setupSite(w http.ResponseWriter, r *http.Request) {
	metadata, err := loadMetadata()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 如果已经完成设置，拒绝请求
	if metadata.SetupCompleted {
		http.Error(w, "站点已经完成设置", http.StatusBadRequest)
		return
	}

	var req SetupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// 验证输入
	if req.SiteName == "" || req.Username == "" || req.Email == "" || req.Password == "" {
		http.Error(w, "所有字段都是必填的", http.StatusBadRequest)
		return
	}

	if len(req.Username) < 3 {
		http.Error(w, "用户名至少3个字符", http.StatusBadRequest)
		return
	}

	if len(req.Password) < 6 {
		http.Error(w, "密码至少6个字符", http.StatusBadRequest)
		return
	}

	// 加密密码
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 创建管理员用户
	adminUser := User{
		ID:           fmt.Sprintf("%d", time.Now().UnixNano()),
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: string(hash),
		Avatar:       "/BG/icon.jpg",
		IsAdmin:      true,
		CreatedAt:    time.Now(),
		Verified:     true,
	}

	// 保存设置
	metadata.SiteName = req.SiteName
	metadata.Admin = &AdminConfig{
		Username:     req.Username,
		PasswordHash: string(hash),
	}
	metadata.Users = append(metadata.Users, adminUser)
	metadata.SetupCompleted = true

	// 创建默认内容（如果还没有）
	if len(metadata.Posts) == 0 {
		// 创建默认文章
		metadata.Posts = []Post{
			{
				ID:        fmt.Sprintf("%d", time.Now().UnixNano()),
				Title:     "欢迎使用 GL-Blog",
				Slug:      "welcome-to-gl-blog",
				Date:      time.Now().Add(-2 * time.Hour),
				CreatedAt: time.Now().Add(-2 * time.Hour),
				UpdatedAt: time.Now().Add(-2 * time.Hour),
				Category:  "技术",
				Tags:      []string{"Go", "前端"},
				Excerpt:   "欢迎使用 GL-Blog，这是一个极简、优雅的个人博客系统。本文介绍了主要特性和使用方法。",
				Cover:     "/BG/BG.png",
			},
			{
				ID:        fmt.Sprintf("%d", time.Now().UnixNano()+1),
				Title:     "Docker 容器化部署指南",
				Slug:      "docker-deployment-guide",
				Date:      time.Now().Add(-1 * time.Hour),
				CreatedAt: time.Now().Add(-1 * time.Hour),
				UpdatedAt: time.Now().Add(-1 * time.Hour),
				Category:  "技术",
				Tags:      []string{"Docker", "后端"},
				Excerpt:   "详细介绍如何使用 Docker 容器化部署 GL-Blog 博客系统，包括镜像构建、容器运行和数据持久化。",
				Cover:     "/BG/BG.png",
			},
			{
				ID:        fmt.Sprintf("%d", time.Now().UnixNano()+2),
				Title:     "我的编程学习心得",
				Slug:      "my-programming-learning-experience",
				Date:      time.Now(),
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
				Category:  "随笔",
				Tags:      []string{"Go", "前端", "后端"},
				Excerpt:   "分享个人编程学习的心得体会，包括学习方法、技术栈选择和一些感悟思考。",
				Cover:     "/BG/BG.png",
			},
		}
	}

	// 设置默认分类和标签（如果还没有）
	if len(metadata.Categories) == 0 {
		metadata.Categories = []string{"技术", "生活", "随笔"}
	}
	if len(metadata.Tags) == 0 {
		metadata.Tags = []string{"Go", "前端", "后端", "Docker"}
	}

	// 设置默认个人信息（如果还没有）
	if metadata.Nickname == "" {
		metadata.Nickname = "Lihu-PR"
	}
	if metadata.Bio == "" {
		metadata.Bio = "Be water my friend"
	}
	if metadata.Avatar == "" {
		metadata.Avatar = "/BG/icon.jpg"
	}
	if metadata.Notice == "" {
		metadata.Notice = "欢迎来到我的博客！"
	}
	if metadata.AboutTitle == "" {
		metadata.AboutTitle = "关于本站"
	}
	if metadata.AboutContent == "" {
		metadata.AboutContent = "# 欢迎来到 GL-Blog\n\n这是一个极简、优雅的个人博客系统。\n\n## 关于博主\n\n我是 Lihu-PR，一名热爱技术的开发者。\n\n**Be water my friend**"
	}

	if err := saveMetadata(metadata); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 创建示例文章的内容文件（如果文章是新创建的）
	if len(metadata.Posts) > 0 {
		sampleContents := map[string]string{
			"welcome-to-gl-blog":                 "# 欢迎使用 GL-Blog\n\n这是您的第一篇示例文章！GL-Blog 是一个极简、优雅的个人博客系统。\n\n## 主要特性\n\n- 🎨 现代化的界面设计\n- 📱 完美的响应式布局\n- ✍️ Markdown 编辑支持\n- 🏷️ 分类和标签管理\n- 📊 访问统计功能\n- 🔐 用户权限管理\n\n开始您的博客之旅吧！",
			"docker-deployment-guide":            "# Docker 容器化部署指南\n\n本文将介绍如何使用 Docker 部署 GL-Blog 博客系统。\n\n## 准备工作\n\n首先确保您的系统已安装 Docker：\n\n```bash\ndocker --version\n```\n\n## 构建镜像\n\n```bash\ndocker build -t gl-blog .\n```\n\n## 运行容器\n\n```bash\ndocker run -d -p 3000:3000 --name gl-blog gl-blog\n```\n\n## 数据持久化\n\n为了保证数据不丢失，建议挂载数据目录：\n\n```bash\ndocker run -d -p 3000:3000 -v ./data:/app/data --name gl-blog gl-blog\n```\n\n这样就完成了 Docker 部署！",
			"my-programming-learning-experience": "# 我的编程学习心得\n\n回顾这些年的编程学习历程，有很多感悟想要分享。\n\n## 学习方法\n\n### 1. 理论与实践并重\n\n不能只看书不动手，也不能只写代码不思考。理论指导实践，实践验证理论。\n\n### 2. 建立知识体系\n\n- 从基础开始，循序渐进\n- 注重知识点之间的联系\n- 定期回顾和总结\n\n### 3. 保持好奇心\n\n技术日新月异，保持学习的热情和好奇心很重要。\n\n## 技术栈选择\n\n目前主要专注于：\n- **后端**: Go, Node.js\n- **前端**: React, Vue\n- **数据库**: MySQL, Redis\n- **运维**: Docker, Kubernetes\n\n## 总结\n\n编程是一个持续学习的过程，享受这个过程比结果更重要。\n\n**Be water my friend** - 像水一样，适应环境，持续流动。",
		}

		// 为每篇示例文章创建内容文件
		for _, post := range metadata.Posts {
			if content, exists := sampleContents[post.Slug]; exists {
				filePath := filepath.Join(postsDir, post.ID+".md")
				// 只有文件不存在时才创建
				if _, err := os.Stat(filePath); os.IsNotExist(err) {
					if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
						log.Printf("创建示例文章内容失败: %v", err)
					}
				}
			}
		}
	}

	// 自动登录
	session, _ := store.Get(r, "session")
	session.Values["admin"] = true
	session.Values["userID"] = adminUser.ID
	session.Values["isAdmin"] = true
	session.Save(r, w)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

type FileInfo struct {
	Name string `json:"name"`
	URL  string `json:"url"`
	Size int64  `json:"size"`
}

func listFiles(w http.ResponseWriter, r *http.Request) {
	files, err := os.ReadDir(uploadsDir)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var fileList []FileInfo
	for _, file := range files {
		if !file.IsDir() {
			info, err := file.Info()
			if err != nil {
				continue
			}
			fileList = append(fileList, FileInfo{
				Name: file.Name(),
				URL:  "/uploads/" + file.Name(),
				Size: info.Size(),
			})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(fileList)
}

func deleteFile(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	filename := vars["filename"]

	// 安全检查
	if strings.Contains(filename, "..") || strings.Contains(filename, "/") {
		http.Error(w, "无效的文件名", http.StatusBadRequest)
		return
	}

	filePath := filepath.Join(uploadsDir, filename)
	if err := os.Remove(filePath); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

func exportDataAPI(w http.ResponseWriter, r *http.Request) {
	if err := exportData(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 读取生成的备份文件
	data, err := os.ReadFile("backup.tar.gz")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=gl-blog-backup-%s.tar.gz", time.Now().Format("20060102-150405")))
	w.Write(data)

	// 删除临时文件
	os.Remove("backup.tar.gz")
}

func importDataAPI(w http.ResponseWriter, r *http.Request) {
	r.ParseMultipartForm(50 << 20) // 50 MB

	file, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()

	// 保存上传的文件
	tempFile := "temp-import.tar.gz"
	dst, err := os.Create(tempFile)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer dst.Close()

	if _, err := io.Copy(dst, file); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	dst.Close()

	// 导入数据
	if err := importData(tempFile); err != nil {
		os.Remove(tempFile)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	os.Remove(tempFile)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

// 用户注册
func userRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Code     string `json:"code"`
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	metadata, err := loadMetadata()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 验证验证码
	if metadata.VerificationCodes == nil {
		http.Error(w, "验证码不存在或已过期", http.StatusBadRequest)
		return
	}

	code, exists := metadata.VerificationCodes[req.Email]
	if !exists || code.Code != req.Code || time.Now().After(code.ExpiresAt) {
		http.Error(w, "验证码不正确或已过期", http.StatusBadRequest)
		return
	}

	// 检查邮箱是否已注册
	for _, user := range metadata.Users {
		if user.Email == req.Email {
			http.Error(w, "该邮箱已被注册", http.StatusBadRequest)
			return
		}
	}

	// 创建用户
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	user := User{
		ID:           fmt.Sprintf("%d", time.Now().UnixNano()),
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: string(hashedPassword),
		Avatar:       "/BG/icon.jpg",
		IsAdmin:      false,
		CreatedAt:    time.Now(),
		Verified:     true,
	}

	metadata.Users = append(metadata.Users, user)

	// 删除已使用的验证码
	delete(metadata.VerificationCodes, req.Email)

	if err := saveMetadata(metadata); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 自动登录
	session, _ := store.Get(r, "session")
	session.Values["userID"] = user.ID
	session.Values["isAdmin"] = user.IsAdmin
	session.Save(r, w)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"user":    user,
	})
}

// 用户登录
func userLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	metadata, err := loadMetadata()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 查找用户
	var user *User
	for i := range metadata.Users {
		if metadata.Users[i].Email == req.Email {
			user = &metadata.Users[i]
			break
		}
	}

	if user == nil {
		http.Error(w, "邮箱或密码错误", http.StatusUnauthorized)
		return
	}

	// 验证密码
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		http.Error(w, "邮箱或密码错误", http.StatusUnauthorized)
		return
	}

	// 设置会话
	session, _ := store.Get(r, "session")
	session.Values["userID"] = user.ID
	session.Values["isAdmin"] = user.IsAdmin
	if user.IsAdmin {
		session.Values["admin"] = true
	}
	session.Save(r, w)

	// 发送登录提醒邮件（异步，不阻塞登录）
	if metadata.SMTP != nil {
		go func() {
			clientIP := getClientIP(r)
			location := getIPLocation(clientIP)
			username := user.Username
			if user.Nickname != "" {
				username = user.Nickname
			}
			sendLoginNotification(metadata.SMTP, user.Email, username, clientIP, location, time.Now())
		}()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"user":    user,
	})
}

// 获取用户信息
func getUserInfo(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	userID, ok := session.Values["userID"].(string)
	if !ok {
		http.Error(w, "未授权", http.StatusUnauthorized)
		return
	}

	metadata, err := loadMetadata()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 查找用户
	for _, user := range metadata.Users {
		if user.ID == userID {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(user)
			return
		}
	}

	http.Error(w, "用户不存在", http.StatusNotFound)
}

// 更新用户资料
func updateUserProfile(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	userID, ok := session.Values["userID"].(string)
	if !ok {
		http.Error(w, "未授权", http.StatusUnauthorized)
		return
	}

	var req struct {
		Username string `json:"username"`
		Nickname string `json:"nickname"`
		Avatar   string `json:"avatar"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	metadata, err := loadMetadata()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 查找并更新用户
	found := false
	isAdmin := false
	for i := range metadata.Users {
		if metadata.Users[i].ID == userID {
			metadata.Users[i].Username = req.Username
			metadata.Users[i].Nickname = req.Nickname
			metadata.Users[i].Avatar = req.Avatar
			isAdmin = metadata.Users[i].IsAdmin
			found = true

			// 如果是管理员，同时更新首页显示的头像和昵称
			if isAdmin {
				metadata.Avatar = req.Avatar
				metadata.Nickname = req.Nickname
			}
			break
		}
	}

	if !found {
		http.Error(w, "用户不存在", http.StatusNotFound)
		return
	}

	if err := saveMetadata(metadata); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

// 获取所有用户（管理员功能）
func getAllUsers(w http.ResponseWriter, r *http.Request) {
	metadata, err := loadMetadata()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metadata.Users)
}

// 更新用户角色（管理员功能）
func updateUserRole(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID  string `json:"userId"`
		IsAdmin bool   `json:"isAdmin"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	metadata, err := loadMetadata()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 查找并更新用户角色
	found := false
	for i := range metadata.Users {
		if metadata.Users[i].ID == req.UserID {
			// 不能修改第一个用户（站长）的权限
			if i == 0 {
				http.Error(w, "不能修改站长权限", http.StatusForbidden)
				return
			}
			metadata.Users[i].IsAdmin = req.IsAdmin
			found = true
			break
		}
	}

	if !found {
		http.Error(w, "用户不存在", http.StatusNotFound)
		return
	}

	if err := saveMetadata(metadata); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

// 删除用户（管理员功能）
func deleteUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID := vars["id"]

	metadata, err := loadMetadata()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 查找用户并检查是否可以删除
	userIndex := -1
	for i, user := range metadata.Users {
		if user.ID == userID {
			// 不能删除第一个用户（站长）
			if i == 0 {
				http.Error(w, "不能删除站长账号", http.StatusForbidden)
				return
			}
			userIndex = i
			break
		}
	}

	if userIndex == -1 {
		http.Error(w, "用户不存在", http.StatusNotFound)
		return
	}

	// 删除用户
	metadata.Users = append(metadata.Users[:userIndex], metadata.Users[userIndex+1:]...)

	if err := saveMetadata(metadata); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

// 发送验证码
func sendVerificationCode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
		Type  string `json:"type"` // register or login
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	metadata, err := loadMetadata()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 检查SMTP配置
	if metadata.SMTP == nil {
		http.Error(w, "邮件服务未配置，请联系管理员", http.StatusInternalServerError)
		return
	}

	// 生成6位验证码
	code := fmt.Sprintf("%06d", time.Now().UnixNano()%1000000)

	// 保存验证码
	if metadata.VerificationCodes == nil {
		metadata.VerificationCodes = make(map[string]VerificationCode)
	}

	metadata.VerificationCodes[req.Email] = VerificationCode{
		Code:      code,
		Email:     req.Email,
		ExpiresAt: time.Now().Add(10 * time.Minute),
		Type:      req.Type,
	}

	if err := saveMetadata(metadata); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 根据类型设置邮件主题和内容
	subject := "邮箱验证码"
	if req.Type == "register" {
		subject = "注册验证码"
	} else if req.Type == "login" {
		subject = "登录验证码"
	} else if req.Type == "password-reset" {
		subject = "找回密码"
	} else if req.Type == "email-change" {
		subject = "账号邮箱换绑"
	}

	body := fmt.Sprintf(`您好！

您的验证码是：%s

验证码将在10分钟后过期，请尽快使用。

如果这不是您的操作，请忽略此邮件。`, code)

	// 发送邮件
	if err := sendEmail(metadata.SMTP, req.Email, subject, body); err != nil {
		http.Error(w, "发送邮件失败："+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

// 获取客户端IP地址
func getClientIP(r *http.Request) string {
	// 尝试从X-Forwarded-For获取
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// 尝试从X-Real-IP获取
	xri := r.Header.Get("X-Real-IP")
	if xri != "" {
		return xri
	}

	// 从RemoteAddr获取
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// 获取IP归属地（简化版，使用IP地址段判断）
func getIPLocation(ip string) string {
	// 检查是否为本地IP
	if ip == "127.0.0.1" || ip == "::1" || strings.HasPrefix(ip, "192.168.") || strings.HasPrefix(ip, "10.") {
		return "本地局域网"
	}

	// 实际使用中可以调用第三方API获取归属地，这里返回简化信息
	return "未知地区"
}

// 发送登录提醒邮件
func sendLoginNotification(smtpConfig *SMTPConfig, email, username, ip, location string, loginTime time.Time) error {
	subject := "博客登录提醒"
	body := fmt.Sprintf(`尊敬的 %s：

您刚刚在 %s 登录了哩虎的技术博客。

登录信息：
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
登录时间：%s
IP地址：  %s
IP归属地：%s
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

如果这不是您本人的操作，请立即修改密码并联系管理员。

此邮件由系统自动发送，请勿直接回复。`,
		username,
		loginTime.Format("2006年01月02日 15:04:05"),
		loginTime.Format("2006年01月02日 15:04:05"),
		ip,
		location)

	return sendEmail(smtpConfig, email, subject, body)
}

// 发送邮件
func getIPGeolocation(ip string) string {
	// 简单的IP归属地查询，实际项目中可以使用更专业的服务
	if ip == "" || ip == "127.0.0.1" || ip == "::1" {
		return "本地"
	}

	// 移除端口号
	if idx := strings.Index(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}

	resp, err := http.Get(fmt.Sprintf("http://ip-api.com/json/%s?lang=zh-CN", ip))
	if err != nil {
		return "未知"
	}
	defer resp.Body.Close()

	var result struct {
		Country string `json:"country"`
		City    string `json:"city"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "未知"
	}

	if result.Country != "" && result.City != "" {
		return fmt.Sprintf("%s %s", result.Country, result.City)
	} else if result.Country != "" {
		return result.Country
	}

	return "未知"
}

func sendEmail(smtpConfig *SMTPConfig, to, subject, body string) error {
	from := smtpConfig.Username
	password := smtpConfig.Password
	host := smtpConfig.Server
	addr := net.JoinHostPort(host, strconv.Itoa(smtpConfig.Port))

	// 构建邮件内容
	msg := []byte("To: " + to + "\r\n" +
		"From: " + smtpConfig.DisplayName + " <" + from + ">\r\n" +
		"Subject: " + subject + "\r\n" +
		"Content-Type: text/plain; charset=UTF-8\r\n" +
		"\r\n" +
		body + "\r\n")

	// 认证信息
	auth := smtp.PlainAuth("", from, password, host)

	// 根据加密方式选择不同的发送方法
	if smtpConfig.Encryption == "SSL" {
		// SSL加密 (端口465)
		tlsConfig := &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: false,
		}

		// 建立TLS连接
		conn, err := tls.Dial("tcp", addr, tlsConfig)
		if err != nil {
			log.Printf("SSL连接失败: %v", err)
			return fmt.Errorf("SSL连接失败: %v", err)
		}
		defer conn.Close()

		// 创建SMTP客户端
		client, err := smtp.NewClient(conn, host)
		if err != nil {
			log.Printf("创建SMTP客户端失败: %v", err)
			return fmt.Errorf("创建SMTP客户端失败: %v", err)
		}
		defer client.Close()

		// 认证
		if err = client.Auth(auth); err != nil {
			log.Printf("SMTP认证失败: %v", err)
			return fmt.Errorf("SMTP认证失败，请检查用户名和密码: %v", err)
		}

		// 设置发件人
		if err = client.Mail(from); err != nil {
			return fmt.Errorf("设置发件人失败: %v", err)
		}

		// 设置收件人
		if err = client.Rcpt(to); err != nil {
			return fmt.Errorf("设置收件人失败: %v", err)
		}

		// 发送邮件正文
		w, err := client.Data()
		if err != nil {
			return fmt.Errorf("发送邮件数据失败: %v", err)
		}
		_, err = w.Write(msg)
		if err != nil {
			return fmt.Errorf("写入邮件内容失败: %v", err)
		}
		err = w.Close()
		if err != nil {
			return fmt.Errorf("关闭邮件写入失败: %v", err)
		}

		client.Quit()
	} else if smtpConfig.Encryption == "TLS" {
		// STARTTLS (端口587)
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			log.Printf("连接SMTP服务器失败: %v", err)
			return fmt.Errorf("连接SMTP服务器失败: %v", err)
		}

		client, err := smtp.NewClient(conn, host)
		if err != nil {
			log.Printf("创建SMTP客户端失败: %v", err)
			return fmt.Errorf("创建SMTP客户端失败: %v", err)
		}
		defer client.Close()

		// STARTTLS
		tlsConfig := &tls.Config{ServerName: host}
		if err = client.StartTLS(tlsConfig); err != nil {
			return fmt.Errorf("STARTTLS失败: %v", err)
		}

		// 认证
		if err = client.Auth(auth); err != nil {
			return fmt.Errorf("SMTP认证失败: %v", err)
		}

		// 设置发件人和收件人
		if err = client.Mail(from); err != nil {
			return fmt.Errorf("设置发件人失败: %v", err)
		}
		if err = client.Rcpt(to); err != nil {
			return fmt.Errorf("设置收件人失败: %v", err)
		}

		// 发送邮件
		w, err := client.Data()
		if err != nil {
			return fmt.Errorf("发送邮件数据失败: %v", err)
		}
		_, err = w.Write(msg)
		if err != nil {
			return fmt.Errorf("写入邮件内容失败: %v", err)
		}
		w.Close()
		client.Quit()
	} else {
		// 无加密
		err := smtp.SendMail(addr, auth, from, []string{to}, msg)
		if err != nil {
			log.Printf("发送邮件失败: %v", err)
			return fmt.Errorf("发送邮件失败: %v", err)
		}
	}

	log.Printf("成功发送邮件到 %s: %s", to, subject)
	return nil
}

// 获取SMTP配置
func getSMTPConfig(w http.ResponseWriter, r *http.Request) {
	metadata, err := loadMetadata()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if metadata.SMTP == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"configured": false,
		})
		return
	}

	// 返回包括密码在内的所有配置（管理员可见）
	config := map[string]interface{}{
		"configured":  true,
		"server":      metadata.SMTP.Server,
		"port":        metadata.SMTP.Port,
		"username":    metadata.SMTP.Username,
		"password":    metadata.SMTP.Password,
		"displayName": metadata.SMTP.DisplayName,
		"encryption":  metadata.SMTP.Encryption,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

// 更新SMTP配置
func updateSMTPConfig(w http.ResponseWriter, r *http.Request) {
	var config SMTPConfig

	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	metadata, err := loadMetadata()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 如果密码为空且已有配置，保留原密码
	if config.Password == "" && metadata.SMTP != nil {
		config.Password = metadata.SMTP.Password
	}

	metadata.SMTP = &config

	if err := saveMetadata(metadata); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

// 测试SMTP配置
func testSMTP(w http.ResponseWriter, r *http.Request) {
	var config SMTPConfig

	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// 发送测试邮件
	testSubject := "SMTP配置测试"
	testBody := "这是一封测试邮件，用于验证SMTP配置是否正确。\n\n如果您收到这封邮件，说明SMTP配置成功！\n\n" + config.DisplayName

	err := sendEmail(&config, config.Username, testSubject, testBody)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "测试邮件已发送",
	})
}

// 获取关于页内容
func getAbout(w http.ResponseWriter, r *http.Request) {
	metadata, err := loadMetadata()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 如果没有设置关于页内容，返回默认内容
	title := metadata.AboutTitle
	content := metadata.AboutContent

	if title == "" {
		title = "关于本站"
	}

	if content == "" {
		content = `# 欢迎来到 GL-Blog

这是一个极致轻量化的个人博客系统，专注于简洁、优雅的写作与阅读体验。

## 关于博主

我是 Lihu-PR，一名热爱技术的开发者。

**Be water my friend** - 这是我的座右铭，意味着保持灵活、适应变化。

## 博客特色

- ✨ **极简设计** - 专注内容，去除冗余
- 🚀 **高性能** - Go 语言开发，响应迅速
- 📝 **Markdown支持** - 原生支持Markdown写作
- 🎨 **优雅动画** - 流畅的交互体验
- 🔒 **隐私保护** - 数据本地存储，完全掌控

## 技术栈

- **后端**: Go 语言
- **前端**: 原生 HTML/CSS/JavaScript
- **部署**: Docker 容器化
- **存储**: 本地文件系统

## 联系方式

如果你有任何问题或建议，欢迎通过以下方式联系我：

- **GitHub**: [Lihu-PR](https://github.com/Lihu-PR)
- **Email**: 17192413622@163.com
- **Bilibili**: [我的B站主页](https://space.bilibili.com/305674742)

---

感谢你的访问！🎉`
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"title":   title,
		"content": content,
	})
}

// 更新关于页内容
func updateAbout(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Title   string `json:"title"`
		Content string `json:"content"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	metadata, err := loadMetadata()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	metadata.AboutTitle = req.Title
	metadata.AboutContent = req.Content

	if err := saveMetadata(metadata); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "关于页更新成功",
	})
}

// 获取服务器状态
func getServerStatus(w http.ResponseWriter, r *http.Request) {
	// 获取真实的系统CPU使用率
	cpuUsage, err := getSystemCPUUsage()
	if err != nil {
		cpuUsage = 0.0
	}

	// 获取真实的系统内存使用情况
	memInfo, err := getSystemMemoryInfo()
	if err != nil {
		memInfo = SystemMemoryInfo{UsedPercent: 0.0, Used: 0, Total: 0}
	}

	// 获取系统负载
	loadAvg, err := getSystemLoadAverage()
	if err != nil {
		loadAvg = 0.0
	}

	// 获取真实的操作系统信息
	osInfo, err := getSystemOSInfo()
	if err != nil {
		osInfo = SystemOSInfo{Name: "Unknown", Arch: runtime.GOARCH}
	}

	status := map[string]interface{}{
		"cpu": map[string]interface{}{
			"usage": fmt.Sprintf("%.1f", cpuUsage),
			"cores": runtime.NumCPU(),
		},
		"memory": map[string]interface{}{
			"usage": fmt.Sprintf("%.1f", memInfo.UsedPercent),
			"used":  fmt.Sprintf("%.1f", float64(memInfo.Used)/(1024*1024*1024)),  // GB
			"total": fmt.Sprintf("%.1f", float64(memInfo.Total)/(1024*1024*1024)), // GB
			"unit":  "GB",
		},
		"load": map[string]interface{}{
			"average": fmt.Sprintf("%.2f", loadAvg),
		},
		"system": map[string]interface{}{
			"os":   osInfo.Name,
			"arch": strings.ToUpper(osInfo.Arch),
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

// 系统内存信息结构体
type SystemMemoryInfo struct {
	Total       uint64
	Used        uint64
	UsedPercent float64
}

// 系统OS信息结构体
type SystemOSInfo struct {
	Name string
	Arch string
}

// 获取系统CPU使用率
func getSystemCPUUsage() (float64, error) {
	if runtime.GOOS == "linux" {
		// 在Docker容器中，/proc/stat 实际上反映的是宿主机的CPU信息
		// 因为容器与宿主机共享内核
		return getLinuxCPUUsage()
	}
	// 其他系统暂时返回0
	return 0.0, fmt.Errorf("unsupported OS")
}

// 获取Linux系统CPU使用率
func getLinuxCPUUsage() (float64, error) {
	// 读取 /proc/stat 两次，计算差值
	stat1, err := readProcStat()
	if err != nil {
		return 0, err
	}

	time.Sleep(100 * time.Millisecond) // 短暂等待

	stat2, err := readProcStat()
	if err != nil {
		return 0, err
	}

	// 计算CPU使用率
	totalDiff := stat2.Total - stat1.Total
	idleDiff := stat2.Idle - stat1.Idle

	if totalDiff == 0 {
		return 0, nil
	}

	cpuUsage := (1.0 - float64(idleDiff)/float64(totalDiff)) * 100.0
	return cpuUsage, nil
}

// CPU统计信息
type CPUStat struct {
	Total uint64
	Idle  uint64
}

// 读取 /proc/stat
func readProcStat() (CPUStat, error) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return CPUStat{}, err
	}

	lines := strings.Split(string(data), "\n")
	if len(lines) == 0 {
		return CPUStat{}, fmt.Errorf("empty /proc/stat")
	}

	// 解析第一行 (总CPU统计)
	fields := strings.Fields(lines[0])
	if len(fields) < 5 || fields[0] != "cpu" {
		return CPUStat{}, fmt.Errorf("invalid /proc/stat format")
	}

	var values []uint64
	for i := 1; i < len(fields) && i <= 8; i++ {
		val, err := strconv.ParseUint(fields[i], 10, 64)
		if err != nil {
			return CPUStat{}, err
		}
		values = append(values, val)
	}

	// user, nice, system, idle, iowait, irq, softirq, steal
	var total uint64
	for _, v := range values {
		total += v
	}

	idle := values[3] // idle time
	if len(values) > 4 {
		idle += values[4] // + iowait
	}

	return CPUStat{Total: total, Idle: idle}, nil
}

// 获取系统内存信息
func getSystemMemoryInfo() (SystemMemoryInfo, error) {
	if runtime.GOOS == "linux" {
		// 在Docker容器中，/proc/meminfo 反映的是宿主机的内存信息
		// 除非容器设置了内存限制
		return getLinuxMemoryInfo()
	}
	return SystemMemoryInfo{}, fmt.Errorf("unsupported OS")
}

// 获取Linux系统内存信息
func getLinuxMemoryInfo() (SystemMemoryInfo, error) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return SystemMemoryInfo{}, err
	}

	lines := strings.Split(string(data), "\n")
	memInfo := make(map[string]uint64)

	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			key := strings.TrimSuffix(fields[0], ":")
			value, err := strconv.ParseUint(fields[1], 10, 64)
			if err == nil {
				memInfo[key] = value * 1024 // 转换为字节
			}
		}
	}

	total := memInfo["MemTotal"]
	free := memInfo["MemFree"]
	buffers := memInfo["Buffers"]
	cached := memInfo["Cached"]
	sReclaimable := memInfo["SReclaimable"]

	// 计算实际使用的内存
	used := total - free - buffers - cached - sReclaimable
	usedPercent := float64(used) / float64(total) * 100.0

	return SystemMemoryInfo{
		Total:       total,
		Used:        used,
		UsedPercent: usedPercent,
	}, nil
}

// 获取系统负载平均值
func getSystemLoadAverage() (float64, error) {
	if runtime.GOOS == "linux" {
		return getLinuxLoadAverage()
	}
	return 0.0, fmt.Errorf("unsupported OS")
}

// 获取Linux系统负载平均值
func getLinuxLoadAverage() (float64, error) {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, err
	}

	fields := strings.Fields(string(data))
	if len(fields) < 1 {
		return 0, fmt.Errorf("invalid /proc/loadavg format")
	}

	loadAvg, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, err
	}

	// 转换为百分比（基于CPU核心数）
	numCPU := float64(runtime.NumCPU())
	loadPercent := (loadAvg / numCPU) * 100.0

	return loadPercent, nil
}

// 获取系统OS信息
func getSystemOSInfo() (SystemOSInfo, error) {
	if runtime.GOOS == "linux" {
		return getLinuxOSInfo()
	}
	return SystemOSInfo{Name: runtime.GOOS, Arch: runtime.GOARCH}, nil
}

// 获取Linux系统OS信息
func getLinuxOSInfo() (SystemOSInfo, error) {
	// 检查是否在Docker容器中运行
	if isRunningInDocker() {
		// 尝试从宿主机获取真实系统信息
		if hostOSInfo, err := getHostOSInfo(); err == nil {
			return hostOSInfo, nil
		}

		// 如果无法获取宿主机信息，检查环境变量
		if hostOS := os.Getenv("HOST_OS"); hostOS != "" {
			return SystemOSInfo{Name: hostOS, Arch: runtime.GOARCH}, nil
		}

		// 最后尝试通过其他方法检测
		return detectHostOSFromContainer()
	}

	// 直接在宿主机上运行，读取本地系统信息
	return readLocalOSInfo()
}

// 读取本地系统信息
func readLocalOSInfo() (SystemOSInfo, error) {
	// 尝试读取 /etc/os-release
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		// 如果失败，尝试其他文件
		data, err = os.ReadFile("/etc/lsb-release")
		if err != nil {
			return SystemOSInfo{Name: "Linux", Arch: runtime.GOARCH}, nil
		}
	}

	return parseOSRelease(string(data))
}

// 解析os-release文件内容
func parseOSRelease(content string) (SystemOSInfo, error) {
	lines := strings.Split(content, "\n")
	osInfo := SystemOSInfo{Name: "Linux", Arch: runtime.GOARCH}

	for _, line := range lines {
		if strings.HasPrefix(line, "NAME=") || strings.HasPrefix(line, "DISTRIB_ID=") {
			// 提取OS名称
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				name := strings.Trim(parts[1], "\"")
				// 简化名称
				if strings.Contains(strings.ToLower(name), "ubuntu") {
					osInfo.Name = "Ubuntu"
				} else if strings.Contains(strings.ToLower(name), "debian") {
					osInfo.Name = "Debian"
				} else if strings.Contains(strings.ToLower(name), "centos") {
					osInfo.Name = "CentOS"
				} else if strings.Contains(strings.ToLower(name), "red hat") || strings.Contains(strings.ToLower(name), "rhel") {
					osInfo.Name = "RHEL"
				} else if strings.Contains(strings.ToLower(name), "fedora") {
					osInfo.Name = "Fedora"
				} else if strings.Contains(strings.ToLower(name), "alpine") {
					osInfo.Name = "Alpine"
				} else {
					// 取第一个单词作为OS名称
					words := strings.Fields(name)
					if len(words) > 0 {
						osInfo.Name = words[0]
					}
				}
				break
			}
		}
	}

	return osInfo, nil
}

// 从容器中检测宿主机OS信息
func getHostOSInfo() (SystemOSInfo, error) {
	// 方法1: 尝试读取宿主机的/proc/version（如果挂载了的话）
	if data, err := os.ReadFile("/proc/version"); err == nil {
		if osInfo := parseKernelVersion(string(data)); osInfo.Name != "Linux" {
			return osInfo, nil
		}
	}

	// 方法2: 尝试通过/proc/sys/kernel/osrelease
	if data, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		if osInfo := parseKernelRelease(string(data)); osInfo.Name != "Linux" {
			return osInfo, nil
		}
	}

	// 方法3: 尝试通过uname命令
	if osInfo, err := getOSInfoFromUname(); err == nil {
		return osInfo, nil
	}

	return SystemOSInfo{}, fmt.Errorf("无法获取宿主机OS信息")
}

// 解析内核版本信息
func parseKernelVersion(version string) SystemOSInfo {
	version = strings.ToLower(version)
	osInfo := SystemOSInfo{Name: "Linux", Arch: runtime.GOARCH}

	if strings.Contains(version, "ubuntu") {
		osInfo.Name = "Ubuntu"
	} else if strings.Contains(version, "debian") {
		osInfo.Name = "Debian"
	} else if strings.Contains(version, "centos") {
		osInfo.Name = "CentOS"
	} else if strings.Contains(version, "red hat") || strings.Contains(version, "rhel") {
		osInfo.Name = "RHEL"
	} else if strings.Contains(version, "fedora") {
		osInfo.Name = "Fedora"
	}

	return osInfo
}

// 解析内核发布信息
func parseKernelRelease(release string) SystemOSInfo {
	release = strings.ToLower(strings.TrimSpace(release))
	osInfo := SystemOSInfo{Name: "Linux", Arch: runtime.GOARCH}

	// 根据内核版本字符串推断发行版
	if strings.Contains(release, "ubuntu") {
		osInfo.Name = "Ubuntu"
	} else if strings.Contains(release, "debian") {
		osInfo.Name = "Debian"
	} else if strings.Contains(release, "el7") || strings.Contains(release, "el8") || strings.Contains(release, "el9") {
		osInfo.Name = "RHEL"
	} else if strings.Contains(release, "fc") {
		osInfo.Name = "Fedora"
	}

	return osInfo
}

// 通过uname命令获取系统信息
func getOSInfoFromUname() (SystemOSInfo, error) {
	// 尝试执行uname -a命令
	cmd := "uname -a 2>/dev/null || echo 'unknown'"
	if output, err := executeCommand(cmd); err == nil {
		output = strings.ToLower(output)
		osInfo := SystemOSInfo{Name: "Linux", Arch: runtime.GOARCH}

		if strings.Contains(output, "ubuntu") {
			osInfo.Name = "Ubuntu"
		} else if strings.Contains(output, "debian") {
			osInfo.Name = "Debian"
		} else if strings.Contains(output, "centos") {
			osInfo.Name = "CentOS"
		} else if strings.Contains(output, "red hat") || strings.Contains(output, "rhel") {
			osInfo.Name = "RHEL"
		} else if strings.Contains(output, "fedora") {
			osInfo.Name = "Fedora"
		}

		return osInfo, nil
	}

	return SystemOSInfo{}, fmt.Errorf("无法执行uname命令")
}

// 执行shell命令
func executeCommand(cmd string) (string, error) {
	// 使用sh执行命令
	out, err := exec.Command("sh", "-c", cmd).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// 从容器中检测宿主机OS的备用方法
func detectHostOSFromContainer() (SystemOSInfo, error) {
	// 检查常见的发行版特征文件或命令
	osInfo := SystemOSInfo{Name: "Linux", Arch: runtime.GOARCH}

	// 方法1: 尝试通过lsb_release命令
	if output, err := executeCommand("lsb_release -i 2>/dev/null | cut -f2"); err == nil {
		output = strings.ToLower(strings.TrimSpace(output))
		if output == "ubuntu" {
			osInfo.Name = "Ubuntu"
			return osInfo, nil
		} else if output == "debian" {
			osInfo.Name = "Debian"
			return osInfo, nil
		}
	}

	// 方法2: 尝试通过hostnamectl命令（如果可用）
	if output, err := executeCommand("hostnamectl 2>/dev/null | grep 'Operating System'"); err == nil {
		output = strings.ToLower(output)
		if strings.Contains(output, "ubuntu") {
			osInfo.Name = "Ubuntu"
			return osInfo, nil
		} else if strings.Contains(output, "debian") {
			osInfo.Name = "Debian"
			return osInfo, nil
		} else if strings.Contains(output, "centos") {
			osInfo.Name = "CentOS"
			return osInfo, nil
		} else if strings.Contains(output, "red hat") || strings.Contains(output, "rhel") {
			osInfo.Name = "RHEL"
			return osInfo, nil
		} else if strings.Contains(output, "fedora") {
			osInfo.Name = "Fedora"
			return osInfo, nil
		}
	}

	// 方法3: 尝试检查特定的发行版文件
	distroFiles := map[string]string{
		"/etc/debian_version": "Debian",
		"/etc/ubuntu-release": "Ubuntu",
		"/etc/redhat-release": "RHEL",
		"/etc/centos-release": "CentOS",
		"/etc/fedora-release": "Fedora",
	}

	for file, distro := range distroFiles {
		if _, err := os.Stat(file); err == nil {
			osInfo.Name = distro
			return osInfo, nil
		}
	}

	// 方法4: 尝试通过cat /etc/issue
	if output, err := executeCommand("cat /etc/issue 2>/dev/null | head -1"); err == nil {
		output = strings.ToLower(output)
		if strings.Contains(output, "ubuntu") {
			osInfo.Name = "Ubuntu"
			return osInfo, nil
		} else if strings.Contains(output, "debian") {
			osInfo.Name = "Debian"
			return osInfo, nil
		} else if strings.Contains(output, "centos") {
			osInfo.Name = "CentOS"
			return osInfo, nil
		} else if strings.Contains(output, "red hat") || strings.Contains(output, "rhel") {
			osInfo.Name = "RHEL"
			return osInfo, nil
		} else if strings.Contains(output, "fedora") {
			osInfo.Name = "Fedora"
			return osInfo, nil
		}
	}

	// 方法5: 通过包管理器检测
	packageManagers := map[string]string{
		"apt":    "Debian/Ubuntu",
		"yum":    "RHEL/CentOS",
		"dnf":    "Fedora",
		"pacman": "Arch",
		"zypper": "openSUSE",
	}

	for pm, distro := range packageManagers {
		if _, err := executeCommand(fmt.Sprintf("which %s 2>/dev/null", pm)); err == nil {
			if pm == "apt" {
				// 进一步区分Debian和Ubuntu
				if _, err := os.Stat("/etc/debian_version"); err == nil {
					if output, err := executeCommand("cat /etc/debian_version 2>/dev/null"); err == nil {
						if strings.Contains(strings.ToLower(output), "ubuntu") {
							osInfo.Name = "Ubuntu"
						} else {
							osInfo.Name = "Debian"
						}
					} else {
						osInfo.Name = "Debian" // 默认为Debian
					}
				}
			} else if strings.Contains(distro, "/") {
				// 对于RHEL/CentOS，尝试进一步区分
				if pm == "yum" {
					if _, err := os.Stat("/etc/centos-release"); err == nil {
						osInfo.Name = "CentOS"
					} else {
						osInfo.Name = "RHEL"
					}
				}
			} else {
				osInfo.Name = distro
			}
			return osInfo, nil
		}
	}

	return osInfo, nil
}

// 检查是否在Docker容器中运行
func isRunningInDocker() bool {
	// 检查 /.dockerenv 文件
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}

	// 检查 /proc/1/cgroup 中是否包含docker
	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		return strings.Contains(string(data), "docker") || strings.Contains(string(data), "containerd")
	}

	return false
}
