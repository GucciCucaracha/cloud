package service

type Service interface {
	Init(token map[string]interface{}) (ServiceObject, error)
	ListDirs(object ServiceObject) ([]ServiceObject, error)
	ListFiles(object ServiceObject) ([]ServiceObject, error)
	ListObjects(object ServiceObject) ([]ServiceObject, error)
	CreateDir(object ServiceObject, dirName string) (ServiceObject, error)
	UploadDir(remotePath string, localPath string) error
	DownloadAll(localPath string) error
	Refresh()
}
