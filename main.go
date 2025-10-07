package main

import (
	"1Pixel/backend/go/cash"
	"1Pixel/backend/go/market"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"log"
	"net/http"

	_ "modernc.org/sqlite"
)

//go:embed frontend/*
var frontendFS embed.FS // 静态资源二进制化

// 配置结构
type Config struct {
	Host   string `json:"host"`   // 服务主机
	Port   int    `json:"port"`   // 服务端口
	DbPath string `json:"dbPath"` // 数据库路径
}

var config = Config{
	Host:   "0.0.0.0",                // 监听IP地址
	Port:   8080,                     // 监听端口
	DbPath: "./backend/data/cash.db", // 数据库路径
}

var db *sql.DB

// 初始化数据库
func initDatabase() error {
	err := cash.InitDatabase(db, config.DbPath)
	if err != nil {
		return err
	}

	// 初始化市场数据库
	err = market.InitMarketDatabase(db)
	if err != nil {
		return err
	}

	return nil
}

// 获取当前余额
func getBalance(w http.ResponseWriter, r *http.Request) {
	cash.GetBalance(db, w, r)
}

// 获取所有交易记录
func getTransactions(w http.ResponseWriter, r *http.Request) {
	cash.GetTransactions(db, w, r)
}

// 添加交易记录
func addTransaction(w http.ResponseWriter, r *http.Request) {
	cash.AddTransaction(db, w, r)
}

// 删除交易记录
func deleteTransaction(w http.ResponseWriter, r *http.Request) {
	cash.DeleteTransaction(db, w, r)
}

// 获取市场参数
func getMarketParams(w http.ResponseWriter, r *http.Request) {
	market.GetMarketParams(db, w, r)
}

// 保存市场参数
func saveMarketParams(w http.ResponseWriter, r *http.Request) {
	market.SaveMarketParams(db, w, r)
}

// 获取背包状态
func getBackpack(w http.ResponseWriter, r *http.Request) {
	market.GetBackpack(db, w, r)
}

// 获取市场物品
func getMarketItems(w http.ResponseWriter, r *http.Request) {
	market.GetMarketItems(db, w, r)
}

// 制作苹果
func makeApple(w http.ResponseWriter, r *http.Request) {
	market.MakeItem(db, w, r, "apple")
}

// 制作木材
func makeWood(w http.ResponseWriter, r *http.Request) {
	market.MakeItem(db, w, r, "wood")
}

// 卖出苹果
func sellApple(w http.ResponseWriter, r *http.Request) {
	market.SellItem(db, w, r, "apple")
}

// 卖出木材
func sellWood(w http.ResponseWriter, r *http.Request) {
	market.SellItem(db, w, r, "wood")
}

// 买入苹果
func buyApple(w http.ResponseWriter, r *http.Request) {
	market.BuyItem(db, w, r, "apple")
}

// 买入木材
func buyWood(w http.ResponseWriter, r *http.Request) {
	market.BuyItem(db, w, r, "wood")
}

func main() {
	// 打开数据库连接
	var err error
	db, err = sql.Open("sqlite", config.DbPath)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}

	// 初始化数据库
	err = initDatabase()
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	// 处理静态资源二进制化
	staticFS, err := fs.Sub(frontendFS, "frontend")
	if err != nil {
		fmt.Printf("处理静态资源二进制化错误: %v\n", err)
		return
	}

	// 处理根路径请求，重定向到 html/index.html
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// 如果请求的是根路径，则重定向到 html/index.html
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/html/index.html", http.StatusFound)
			return
		}
		// 其他路径由静态文件服务器处理
		http.FileServer(http.FS(staticFS)).ServeHTTP(w, r)
	})

	// api:cash: 交易记录
	http.HandleFunc("/api/cash/balance", getBalance)
	http.HandleFunc("/api/cash/transactions", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			getTransactions(w, r)
		case "POST":
			addTransaction(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})
	http.HandleFunc("/api/cash/transactions/delete", deleteTransaction)

	// 市场相关路由
	http.HandleFunc("/api/market/params", getMarketParams)
	http.HandleFunc("/api/market/save-params", saveMarketParams)
	http.HandleFunc("/api/market/backpack", getBackpack)
	http.HandleFunc("/api/market/items", getMarketItems)
	http.HandleFunc("/api/market/make-apple", makeApple)
	http.HandleFunc("/api/market/make-wood", makeWood)
	http.HandleFunc("/api/market/sell-apple", sellApple)
	http.HandleFunc("/api/market/sell-wood", sellWood)
	http.HandleFunc("/api/market/buy-apple", buyApple)
	http.HandleFunc("/api/market/buy-wood", buyWood)

	// 启动服务器
	fmt.Printf("1Pixel server starting on port %d\n", config.Port)
	fmt.Printf("Visit http://%s:%d or http://localhost:%d\n", config.Host, config.Port, config.Port)
	err = http.ListenAndServe(fmt.Sprintf("%s:%d", config.Host, config.Port), nil)
	if err != nil {
		fmt.Printf("Error starting server: %v\n", err)
	}
}
