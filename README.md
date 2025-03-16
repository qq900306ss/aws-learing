# 啟動OS 

## SET OS 
go env -w GOOS=linux

## set go 架構 arm64
go env -w GOARCH=arm64 


## build

go build -tags lambda.norpc -o bootstrap main.go

