# README.md

## Deploy

Windows 10 -> version

```plain
golang-windows 1.21.0
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
C:\Users\Administrator\Downloads\1Pixel>
C:\Users\Administrator\Downloads\1Pixel>REM production mode (Remove debug symbol)
C:\Users\Administrator\Downloads\1Pixel>go build -ldflags='-s -w' -o 1Pixel.exe main.go
```