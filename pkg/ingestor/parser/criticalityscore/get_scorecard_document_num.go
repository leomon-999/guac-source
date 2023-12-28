package criticalityscore

import (
	"context"
	"io/ioutil"
	"os"

	"github.com/guacsec/guac/pkg/logging"
)

/*
获取scorecard文件夹文件数量
*/
func getScorecardDocsNum(ctx context.Context) int {
	logger := logging.FromContext(ctx)
	//目录路径
	gopath := os.Getenv("GOPATH")
	dirPath := gopath + "/src/github.com/guacsec/guac-data/scorecard"

	files, err := ioutil.ReadDir(dirPath)
	if err != nil {
		logger.Errorf("读取目录失败:", err)
	}

	if len(files) == 0 || len(files) == 1 {
		return 1
	}
	fileCount := 0
	for _, file := range files {
		// 如果是普通文件
		if file.Mode().IsRegular() {
			fileCount++
		}
	}

	logger.Infof("文件数量:", fileCount)
	return fileCount
}
