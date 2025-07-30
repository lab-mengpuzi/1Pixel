# 1Pixel

## Dot

```plain
1. ^ [2025.07 地方 党政 领导干部 生态环境保护责任制 规定 (试行) | 中国政府网](https://www.gov.cn/zhengce/202507/content_7034371.htm)
2. ^ [4.1] 坚持 党政同责 / 齐抓共管 / 失职追责 / 增强 共抓 生态文明 建设 的 整体 效能
3. ^ [4.2] 坚持 管 发展 必须 抓 环保 / 管 生产 必须 抓 环保 / 管 行业 必须 抓 环保 守 土 有 责 / 守 土 尽 责
4. ^ [4.3] 坚持 树立 及 践行 正确 政绩观 遵循 自然规律 坚决 摒弃 以 牺牲 生态环境 换取 一 时 一 地 经济 增长 的 做法
5. ^ [4.4] 坚持 以 人民 为 中心 加快 解决 人民群众 反映 强烈 的 突出 生态环境 问题 做到 生态 惠 民 / 生态 利 民 / 生态 为 民
6. ^ [4.5] 坚持 激励 及 约束 并重 健全 精准 科学 的 追责 机制 激励 干部 敢于担当 / 积极作为
```

## Dot

```plain
1. ^ 先 立 后 破 不 立 不 破
2. ^ 以 企业 经营 日常 为 小 切口 丰富 / 完善 国际中国哲学社会科学 理论 体系 势 在 必 行 / 毫 不 动 摇
```

## Deploy

Windows 10 -> version

```plain
golang-windows 1.21.0
nginx-windows  1.24.0
```

Windows 10 -> run

```cmd
C:\Users\Administrator\Downloads\1Pixel>REM Install Dependency
C:\Users\Administrator\Downloads\1Pixel>go mod tidy
C:\Users\Administrator\Downloads\1Pixel>
C:\Users\Administrator\Downloads\1Pixel>REM Run main.go
C:\Users\Administrator\Downloads\1Pixel>go run main.go
```

Windows 10 -> build

```cmd
C:\Users\Administrator\Downloads\1Pixel>REM windows build
C:\Users\Administrator\Downloads\1Pixel>go build -o 1Pixel.exe main.go
C:\Users\Administrator\Downloads\1Pixel>
C:\Users\Administrator\Downloads\1Pixel>REM linux build
C:\Users\Administrator\Downloads\1Pixel>set GOOS=linux & set GOARCH=amd64 & go build -o 1Pixel main.go
```