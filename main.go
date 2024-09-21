package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/willf/bloom"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var (
	DB *gorm.DB
	BF *bloom.BloomFilter
)

func InitDB(ctx context.Context) error {
	newLogger := logger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags), // io writer
		logger.Config{
			SlowThreshold:             time.Second, // 慢SQL阈值
			LogLevel:                  logger.Info, // 日志等级
			IgnoreRecordNotFoundError: true,        // 忽略 ErrRecordNotFound error
			ParameterizedQueries:      false,       // SQL 日志中不包含参数
			Colorful:                  true,        // 启用颜色
		},
	)
	dsn := "host=localhost port=5432 user=your_user password=your_passwd dbname=your_dbname sslmode=disable TimeZone=Asia/Shanghai"

	conn, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: newLogger,
	})
	if err != nil {
		return err
	}
	pgDB, err := conn.DB()
	if err != nil {
		return err
	}
	pgDB.SetMaxOpenConns(100)
	pgDB.SetMaxIdleConns(10)

	DB = conn

	return nil
}

func main() {
	ctx := context.Background()
	err := InitDB(ctx)
	if err != nil {
		log.Fatalln(err)
	}

	tm := time.Now()
	//初始化布隆过滤器
	createBloomFilter(2000000, 0.01)
	log.Printf("初始化布隆过滤器花费时间:%v", time.Since(tm))

	g := gin.New()
	g.Use(gin.Logger(), gin.Recovery())

	g.POST("/simple/search", SimpleSearch)
	g.POST("/bloom/search", BloomSearch)

	log.Fatalln(g.Run(":8080"))
}

type searchReq struct {
	Value string `json:"value"`
}

type searchRes struct {
	Code    int    `json:"code"`
	Message string `json:"msg"`
	Data    any    `json:"data"`
}

type ThreatInfo struct {
	Category string `json:"category"`
	GEO      string `json:"geo"`
	Value    string `json:"value"`
	Type     string `json:"type"`
	Source   string `json:"source"`
}

func SimpleSearch(c *gin.Context) {
	var (
		req    searchReq
		res    searchRes
		threat ThreatInfo
	)
	err := c.BindJSON(&req)
	if err != nil {
		res.Code = 1000
		res.Message = err.Error()
		c.JSON(200, res)
		return
	}
	if tx := DB.Table("your_table").Where("value = ?", req.Value).Find(&threat); tx.Error != nil {
		res.Code = 1000
		res.Message = tx.Error.Error()
		c.JSON(200, res)
		return
	}
	res.Code = 1001
	res.Message = "sucess"
	res.Data = threat
	c.JSON(200, res)
}
func BloomSearch(c *gin.Context) {
	var (
		req    searchReq
		res    searchRes
		threat ThreatInfo
	)
	err := c.BindJSON(&req)
	if err != nil {
		res.Code = 1000
		res.Message = err.Error()
		c.JSON(200, res)
		return
	}
	// 布隆过滤器判断，存在则查询数据库
	if BF.Test([]byte(req.Value)) {
		if tx := DB.Table("your_table").Where("value = ?", req.Value).Find(&threat); tx.Error != nil {
			res.Code = 1000
			res.Message = tx.Error.Error()
			c.JSON(200, res)
			return
		}
	}
	res.Code = 1001
	res.Message = "sucess"
	res.Data = threat
	c.JSON(200, res)
}

func createBloomFilter(expectedItems uint, falsePositiveRate float64) {
	var threat ThreatInfo
	// 初始化布隆过滤器
	BF = bloom.NewWithEstimates(expectedItems, falsePositiveRate)

	// 从数据库中查询所有恶意IP地址,添加到布隆过滤器中
	rows, err := DB.Table("your_table").Select("value").Rows()
	if err != nil {
		log.Fatalln(err)
	}
	defer rows.Close()
	for rows.Next() {
		if err := rows.Scan(&threat.Value); err != nil {
			log.Println(err)
		} else {
			BF.Add([]byte(threat.Value))
		}
	}
}
