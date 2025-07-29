# 1Pixel

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