package main

import (
	"fmt"
	"github.com/gogf/gf/crypto/gdes"
	"github.com/gogf/gf/os/gfile"
	"github.com/gogf/gf/os/gtime"
	"github.com/gogf/gf/text/gstr"
	"os"
)

var (
	// key长度需要小于8
	key         = []byte("111111111")
	opMode      = -1
	fileId      = -1
	currentPath = gfile.SelfDir()
)

func main() {
	fmt.Printf("文件树洞\n 2021-06-15 前不可以访问加密文件～～～\n")
	fmt.Printf("请选择工作模式:\n1.文件加密\n2.文件解密\n请输入操作序号:")
	_, _ = fmt.Scanf("%d", &opMode)
	list, _ := gfile.ScanDirFile(currentPath, "*", false)
	fmt.Printf("当前目录文件列表\n")
	for k, v := range list {
		fmt.Printf("%d. %s\n", k, v)
	}
	fmt.Printf("请选择要操作的文件序号:")
	_, _ = fmt.Scanf("%d", &fileId)
	if fileId < 0 || opMode < 0 {
		fmt.Printf("操作模式错误\n")
		os.Exit(0)
	}
	switch opMode {
	case 1:
		fmt.Printf("加密文件:%s...\n", list[fileId])
		EncryptFile(list[fileId])
	case 2:
		fmt.Printf("解密文件:%s...\n", list[fileId])
		CheckAllowDecrypt(list[fileId])
	default:
		fmt.Printf("操作模式错误\n")
		os.Exit(0)
	}
}

func CheckAllowDecrypt(file string) {
	currentTime := gtime.Now()
	targetTime, err := gtime.StrToTime("2020-06-15T00:00:00+08:00")
	if err != nil {
		fmt.Printf("生成解锁时间戳异常:%s\n", err.Error())
		os.Exit(-1)
	}
	fmt.Printf("当前时间:%s\n", currentTime.String())
	fmt.Printf("允许解锁时间:%s\n", targetTime.String())
	if currentTime.After(targetTime) {
		fmt.Printf("时间达到解锁标准，开始解密文件\n")
		DecryptFile(file)
		return
	}
	remainTime := targetTime.Sub(currentTime)
	fmt.Printf("时间还没到,过去的就让他过去吧～,再等%s天！一起都过去了再说\n", fmt.Sprint(remainTime.Hours()/24))
}
func DecryptFile(encryptedFile string) {
	if !gstr.Contains(encryptedFile, ".encrypt") {
		fmt.Println("加密文件名错误,需要以.encrypt结尾")
		os.Exit(-1)
	}
	fmt.Printf("开始解密文件%s\n", encryptedFile)
	if !gfile.Exists(encryptedFile) {
		fmt.Printf("需要解密的文件不在当前目录\n")
		os.Exit(-1)
	}
	decryptedData, err := gdes.DecryptECB(gfile.GetBytes(encryptedFile), key, gdes.PKCS5PADDING)
	if err != nil {
		fmt.Printf("文件解密失败:%s\n", err.Error())
		os.Exit(-1)
	}
	outputFileName := gstr.Replace(encryptedFile, ".encrypt", "", 1)
	fmt.Printf("生成解密后的文件:%s\n", outputFileName)
	if err := gfile.PutBytes(outputFileName, decryptedData); err != nil {
		fmt.Printf("解密后的数据写入当前目录失败:%s\n", err.Error())
		os.Exit(-1)
	}
	if err := gfile.Remove(encryptedFile); err != nil {
		fmt.Printf("删除加密源文件失败:%s\n", err.Error())
	}
}

func EncryptFile(sourceFile string) {
	fmt.Printf("开始加密文件%s\n", sourceFile)
	if !gfile.Exists(sourceFile) {
		fmt.Printf("需要加密的文件不在当前目录\n")
		os.Exit(-1)
	}
	encryptedData, err := gdes.EncryptECB(gfile.GetBytes(sourceFile), key, gdes.PKCS5PADDING)
	if err != nil {
		fmt.Printf("文件加密失败:%s\n", err.Error())
		os.Exit(-1)
	}
	fmt.Printf("生成加密后的文件:%s\n", sourceFile+".encrypt")
	if err := gfile.PutBytes(sourceFile+".encrypt", encryptedData); err != nil {
		fmt.Printf("加密后的数据写入当前目录失败:%e\n", err)
		os.Exit(-1)
	}
	if err := gfile.Remove(sourceFile); err != nil {
		fmt.Printf("删除原始文件失败:%s\n", err.Error())
	}
}
