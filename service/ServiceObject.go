package service

type ServiceObject interface {
	File() bool
	SomeBool() bool
	Dir() bool
	ReturnId() string
	ReturnPath() string
	ReturnName() string
	ReturnSize() int
	GetParent() *ServiceObject
	SetParent(object *ServiceObject)
	Download(localPath string) error
	Upload(localFile string) error
	SomeAction() error
	OtherAction() error
	Remove() error
}
