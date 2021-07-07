// Package myService developed to demonstrate the style of writing
// code to the employer and contains just part of full code.
// Full library contains functions for implementation http (socks),
// cryptography, json, I/O and simple data conversion.
package myService

import (
	"C"
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/matishsiao/goInfo"
	"github.com/pkg/errors"
	"golang.org/x/net/proxy"
	"./service"
	"io"
	"io/ioutil"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

// describes building http requests
const (
	ToBridge int = 0 // connect to bridge flag
	ToHost   int = 1 // connect to host flag
	ToWeb    int = 2 // connect to web app flag
)

// describes action of crypto algorithm
const (
	Decrypt int = 0 // decrypt the name flag
	Encrypt int = 1 // encrypt the name flag
)

// manipulation values of data size
const (
	ShardChallenges    int = 4       // number shard for challenges value in merkle tree
	ShardMultiplesBack int = 4       // value for count minimum shard size
	MinimumShardSize   int = 2097152 // minimal size for data and parity shards
)

// MyService implements accessing projects.
type MyService struct {
	root   service.ServiceObject
	Access Access
	system System
}

// Access describes the structure of auth data
type Access struct {
	BucketMagic   []byte
	BasicKey      string
	BearerKey     string
	MnemonicHuman string
	BucketID      string
	MagicIV       string
	MagicSalt     string
	CryptoKey     string
	IndexString   string `json:"index"`
	RootID        string `json:"root_folder_id"`
	HideID        string `json:"id"`
	Proxy         string
	UserProxy     string
	PasswordProxy string
}

// System store user's OS
type System struct {
	OperationSystem string
}

// FileData describes the file metrics
type FileData struct {
	RandomValue          []byte
	TotalShards          int
	ShardSize            int
	FileSize             int
	TotalDataShards      int
	TotalParityShards    int
	TmpFileName          string
	ParityCryptoPath     string
	TmpPath              string
	ParityCryptoName     string
	FileCryptoName       string
	EncryptionNameBucket string
}

var someBool bool

// ErrorSimpleHandler wraps simple error and return debug information in console and user's message to GUI
func ErrorSimpleHandler(err error, message string) error {
	fmt.Printf("[ERROR] %s: %v\n", message, err)
	return errors.New(message)
}

// ErrorResponse wraps http response error and return error message with status code and url
func ErrorResponse(err error, url, message string, code int) error {
	userMessage := errors.New("Server's error response, try again")
	if code < 500 {
		userMessage = errors.Errorf("Bad response from server. Status code: %d\n%s\n", code, message)
	}
	fmt.Printf("\n[ERROR] Wrong server answer %s\nStatus code: %d\nerror: %v\n", url, code, err)
	return userMessage
}

// ErrorMkdir wraps creating path errors and return nil if directory is exist and err in other case
func ErrorMkdir(err error, path string) error {
	if err == nil {
		return nil
	}
	xErr := "mkdir " + path + ": Cannot create a file when that file already exists."
	if err.Error() == xErr {
		fmt.Println("[WARNING] Create directory warning: directory already exist.")
		return nil
	}
	fmt.Printf("[WARNING] Create directory error: %v\n", err)
	return err
}

// Init initialise MyService
func (ix *MyService) Init(token map[string]interface{}) (service.ServiceObject, error) {
	// declare structs for user's data
	type Users struct {
		FolderRoot int `json:"root_folder_id"`
	}

	type folderIDResp struct {
		User Users `json:"user"`
	}

	type folderIDReq struct {
		Email    string `json:"email"`
		Mnemonic string `json:"mnemonic"`
	}

	// struct for parse storage ID
	type responseMySrv struct {
		ID string
	}

	// declare hardcode variable for crypto functions
	BucketMagic := []byte{
		66, 150, 71, 16, 50, 114, 88, 160, 163, 35, 154, 65, 162, 213, 226, 215, 70, 138, 57, 61, 52, 19, 210, 170, 38,
		164, 162, 200, 86, 201, 2, 81,
	}
	MagicIv := "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
	MagicSalt := "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
	CryptoKey := "xxxxxxxxxxxxxxxx"
	someBool = true
	getSysInfo := goInfo.GetInfo() // get info about system (for get OS)

	var (
		parseResponse []responseMySrv
		client        *http.Client
		err           error
		usrEmail      string
		hashPass      string
		mnemonic      string
		basicKey      string
		bearerKey     string
		_proxy        string
		bucketID      string
		rootID        string
	)

	fidr := &folderIDReq{}  // create pointer to the structure for request
	fids := &folderIDResp{} // create pointer to the structure for parse response
	// Initialize user data from json
	usrEmail = token["Bridge_User"].(string)
	hashPass = token["Bridge_Password"].(string)
	_proxy = token["proxy"].(string)
	mnemonic = token["Encryption_Key"].(string)
	bearerKey = "Bearer " + token["token"].(string)
	basicKey, err = keyBasic(hashPass, usrEmail) // get key for basic authentication
	bucketURL := GetURL() + "/MyService"         // Set bucket URL
	// get bucket ID from bridge
	requestBody, codeStatus, err := GetRequest(bucketURL, basicKey, ToBridge, _proxy)
	if err != nil || codeStatus != 200 {
		return nil, err
	}
	// parse response with bucket ID
	err = json.Unmarshal(requestBody, &parseResponse)
	bucketID = parseResponse[0].ID
	URL := "https://MyService.MyService/" // Set remote URL for root id request
	availableCode := []int{200, 201, 203} // Set available response codes
	// Set fields for request (want get root id in response)
	fidr.Mnemonic = ""
	fidr.Email = usrEmail
	jsonMarsh, err := json.Marshal(fidr)

	// Check proxy usage and set if true or create no-proxy client
	client, err = proxyResolution(_proxy)
	if err != nil {
		fmt.Println("[ERROR] From initialization: Cannot create http client")
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, URL, bytes.NewBuffer(jsonMarsh))
	if err != nil {
		fmt.Println(err)
	}
	// set headers for request
	req.Header.Add("Authorization", bearerKey)
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:87.0) Gecko/20100101 Firefox/87.0")
	req.Header.Add("MyService-version", "1.0.0")
	req.Header.Add("MyService-client", "MyService")
	req.Header.Set(
		"UserEmail-Agent",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36",
	)
	req.Header.Add("Origin", "https://MyService.com")
	req.Header.Add("Sec-Fetch-Site", "same-origin")
	req.Header.Add("Sec-Fetch-Mode", "cors")
	req.Header.Add("Sec-Fetch-Dest", "empty")
	// make request
	resp, err := client.Do(req)
	if err != nil {
		return nil, ErrorResponse(err, URL, "", resp.StatusCode)
	}
	body, err := ioutil.ReadAll(resp.Body)
	// Check the availability of the resource by the response code
	checkCode := contains(availableCode, resp.StatusCode)
	if err != nil || checkCode == false {
		return nil, ErrorResponse(err, URL, "Cannot get root id.", resp.StatusCode)
	}
	// get user's root id
	err = json.Unmarshal(body, &fids)
	if err != nil {
		return nil, errors.Wrapf(err, "Can`t get body request!\n")
	}
	rootID = fmt.Sprintf("%v", fids.User.FolderRoot)
	// initialize OS, user's service data, root service data respectively
	operationSystemInit := System{
		OperationSystem: getSysInfo.Kernel,
	}
	// set user access data
	userAccess := Access{
		MnemonicHuman: mnemonic,
		RootID:        rootID,
		BucketMagic:   BucketMagic,
		MagicIV:       MagicIv,
		MagicSalt:     MagicSalt,
		CryptoKey:     CryptoKey,
		BasicKey:      basicKey,
		BucketID:      bucketID,
		BearerKey:     bearerKey,
		Proxy:         _proxy,
	}
	// set root data
	rootObj := service.ServiceObject(
		&MyServiceObject{
			Name:          "/",
			Path:          "/",
			Parent:        nil,
			ParentService: ix,
			IsBucket:      true,
			Id:            rootID,
		},
	)

	ix.system = operationSystemInit
	ix.root = rootObj
	ix.Access = userAccess
	return rootObj, nil
}

// Tree create an cache-entity for saving listing ALL Tree
var Tree []service.ServiceObject

// SwitchingTree create an cache-entity for saving last Tree state
var SwitchingTree []service.ServiceObject

//ListObjects func make request to bridge and return files and dirs objects
func (ix *MyService) ListObjects(object service.ServiceObject) ([]service.ServiceObject, error) {
	var FilesAndDirs []service.ServiceObject
	var err error
	var curTree []service.ServiceObject
	// check cache Tree
	if Tree == nil {
		// build Tree if tree is empty
		Tree, SwitchingTree, err = ix.BuildTree()
		if err != nil {
			return nil, err
		}
	}
	// checking SOME condition
	if someBool {
		curTree = SwitchingTree
	} else {
		curTree = Tree
	}
	// find objects into tree for selected directory
	for _, obj := range curTree {
		parent := *obj.GetParent()
		parentWebId, _ := splitId(parent.ReturnId())
		parentId := parentWebId
		objectWebId, _ := splitId(object.ReturnId())
		if objectWebId == parentId {
			FilesAndDirs = append(FilesAndDirs, obj)
		}
	}
	return FilesAndDirs, nil
}

// ListLib for BuildTree()
type ListLib struct {
	Filename string
	Size     int
	Id       string
	Created  string
}

// FilesForID describes the structure of getting web-file-data
type FilesForID struct {
	IDDir     int    `json:"folder_id"`
	FileLibID string `json:"fileId"`
	NameParse string `json:"name"`
	TYPE      string `json:"type"`
	Size      int    `json:"size"`
	FileWebId int    `json:"id"`
}

// ListCommonFolders for BuildTree()
type ListCommonFolders struct {
	Id       int
	ParentId int `json:"parent_id"`
	Name     string
}

// ListCommonFilesAndFolders for BuildTree()
type ListCommonFilesAndFolders struct {
	Folders         []ListCommonFolders `json:"folders"`
	FilesForParseID []FilesForID        `json:"files"`
}

// BuildTree create file's tree in storage for list
func (ix *MyService) BuildTree() ([]service.ServiceObject, []service.ServiceObject, error) {
	// create pointer to the structure for unmarshalling received server data
	lcDir := &ListCommonFilesAndFolders{}
	liDir := &[]ListLib{}
	// initialize different maps for __ trees
	oneMap := make(map[string]interface{})
	twoMap := make(map[string]interface{})

	var (
		fileWebList    []service.ServiceObject
		fileBucketList []service.ServiceObject
		dirs           []service.ServiceObject
		fol            service.ServiceObject
		objectPath     string
		id             string
		bucket         bool
		dir            bool
	)

	// set URLs for requests
	URLCommonList := "https://MyService/path_1"
	URLLib := "https://MyService/" + ix.Access.BucketID + "/path_2"
	// bucket in MyService context mean root folder in storage
	bucket = true
	dir = false
	// make GET request by folder id and return json body with _ folder's objects
	bodyUrlCommonList, codeStatus, err := GetRequest(URLCommonList, ix.Access.BearerKey, 0, ix.Access.Proxy)
	if err != nil || codeStatus != 200 {
		return nil, nil, err
	}
	err = json.Unmarshal(bodyUrlCommonList, &lcDir)
	if err != nil {
		return nil, nil, ErrorSimpleHandler(err, "List files error: Cannot unmarshal response.")
	}

	// make GET request by folder id and return json body with _ folder's objects
	bodyUrlLib, codeStatus, err := GetRequest(URLLib, ix.Access.BasicKey, 0, ix.Access.Proxy)
	if err != nil || codeStatus != 200 {
		return nil, nil, err
	}
	err = json.Unmarshal(bodyUrlLib, &liDir)
	if err != nil {
		return nil, nil, ErrorSimpleHandler(err, "List files error: Cannot unmarshal response.")
	}
	// cache structure for parents
	parentMap := make(map[string]service.ServiceObject)
	parentMap[strings.Split(ix.root.ReturnId(), ";")[0]] = ix.root
	// iterate through the directories and define the object
	for _, element := range lcDir.Folders {
		if element.ParentId != 0 {
			parent := service.ServiceObject(
				&MyServiceObject{
					Id:     fmt.Sprintf("%v", element.ParentId),
					Parent: &ix.root,
				},
			)
			id = fmt.Sprintf("%v", element.Id)
			name, err := EnDecryptionWebName(
				ix.Access.CryptoKey, fmt.Sprintf("%v", element.ParentId), ix.Access.MagicIV, ix.Access.MagicSalt,
				element.Name,
				Decrypt,
			)
			folderPath := objectPath + "/" + name
			transformPath := strings.Replace(folderPath, "//", "/", -1)
			if err != nil {
				_ = ErrorSimpleHandler(err, "Cannot decrypt file name.")
			}
			fol = service.ServiceObject(
				&MyServiceObject{
					Name:            name,
					Parent:          &parent,
					ParentService:   ix,
					IsBucket:        bucket,
					IsDir:           dir,
					someConditional: false,
					Id:              id,
					ParentID:        fmt.Sprintf("%v", element.ParentId),
					Path:            transformPath,
				},
			)
			dirs = append(dirs, fol)
			parentMap[strings.Split(fol.ReturnId(), ";")[0]] = fol
		}
	}
	// collect lib-file-IDs from web-listing-files
	var libIds []string
	for _, r := range lcDir.FilesForParseID {
		libIds = append(libIds, r.FileLibID)
	}
	// make double loop to detect __ files
	for _, libElement := range *liDir {
		if containStr(libIds, libElement.Id) {
			for _, webElement := range lcDir.FilesForParseID {
				if webElement.FileLibID == libElement.Id { // append _ files to list by _
					parent := parentMap[fmt.Sprintf("%v", webElement.IDDir)]
					id = fmt.Sprintf("%v", webElement.FileWebId)
					size := strconv.Itoa(webElement.Size)
					// get decrypt name
					name, err := EnDecryptionWebName(
						ix.Access.CryptoKey, fmt.Sprintf("%v", webElement.IDDir), ix.Access.MagicIV,
						ix.Access.MagicSalt,
						webElement.NameParse,
						Decrypt,
					)
					if err != nil {
						return nil, nil, ErrorSimpleHandler(err, "Cannot decrypt name for list.")
					}
					file := service.ServiceObject(
						&MyServiceObject{
							Name:            name + "." + webElement.TYPE,
							Id:              id,
							Parent:          &parent,
							IsFile:          true,
							someConditional: false,
							ParentService:   ix,
							Size:            size,
							ParentID:        fmt.Sprintf("%v", webElement.IDDir),
							ApiId:           webElement.FileLibID,
						},
					)
					fileWebList = append(fileWebList, file)
					break
				}
			}
		} else {
			id = fmt.Sprintf("%v", libElement.Id)
			// decrypt lib-file-name (return FULL file`s path)
			name, err := ix.DecryptLibName(libElement.Filename)
			// declare checker for the presence of second encryption
			IsTFA := regexp.MustCompile(`^ONzgORtJ77qI28jDnr`).MatchString
			if IsTFA(name) {
				split := strings.Split(name, ".")
				tempName, err := EnDecryptionWebName(
					ix.Access.CryptoKey, ix.Access.RootID, ix.Access.MagicIV, ix.Access.MagicSalt, split[0], Decrypt,
				)
				if err != nil {
					return nil, nil, ErrorSimpleHandler(err, "Cannot decrypt lib-name for list.")
				}
				// declare checker of correctness of the decrypted text
				var IsAlpha = regexp.MustCompile(`^[A-Za-z0-9-]+$`).MatchString
				if !IsAlpha(tempName) {
					tempName = "file_" + fmt.Sprintf("%v", libElement.Created)
				}
				name = tempName + "." + split[1]
			}
			if err != nil {
				return nil, nil, ErrorSimpleHandler(err, "Cannot decrypt lib-name for list.")
			}
			// check path separator
			checkPath, err := regexp.MatchString(`/|\\`, name)
			if err != nil {
				return nil, nil, ErrorSimpleHandler(err, "Cannot build file's list.")
			}
			// get file name + postfix (aka file web id: need for bridge upload func)
			if checkPath == true {
				regular := regexp.MustCompile(`(\\([^\\])*)|(/([^/])*)`)
				fistWork := regular.FindAllString(name, -1)
				name = fmt.Sprintf("%s", fistWork[len(fistWork)-1][1:])
			}
			// next clear the postfix (file web id) from lib-name
			checkPostfix, err := regexp.MatchString(`\d{7}$`, name)
			if err != nil {
				return nil, nil, ErrorSimpleHandler(err, "Cannot build file's list.")
			}

			// check for a postfix (As a postfix, the file web id for the uniqueness of the name in bucket)
			if checkPostfix == true {
				name = name[:len(name)-7]
			}
			files := services.ServiceObject(
				&MyServiceObject{
					Name:            name,
					Id:              id,
					Path:            "/",
					Parent:          &ix.root,
					IsFile:          true,
					someConditional: true,
					ParentService:   ix,
					Size:            "NULL",
					ApiId:           id,
				},
			)
			fileBucketList = append(fileBucketList, files)
		}
	}
	visionList := listFiller(dirs, nil, fileWebList)
	shadowList := listFiller(dirs, fileBucketList, fileWebList)
	for _, elem := range visionList {
		parentObject := *elem.GetParent()
		parent := parentMap[strings.Split(parentObject.ReturnId(), ";")[0]]
		elem.SetParent(&parent)
		oneMap[strings.Split(elem.ReturnId(), ";")[0]] = elem
	}
	for _, elem := range shadowList {
		twoMap[strings.Split(elem.ReturnId(), ";")[0]] = elem
	}
	return shadowList, visionList, err
}

type Mirrors struct {
	Establishes []Established `json:"established"`
}

type Established struct {
	ShardHash string `json:"shardHash"`
	Contract  `json:"contract"`
}

type Contract struct {
	FarmerId string `json:"farmer_id"`
}

/*
PostRequest make a POST request. The flag defines the request headers, depending on where the request will be sent
(to the bridge or to the host). There is support for SOCKS5 proxy and passing the request body as a parameter.
Returns the server response body and response status.
*/
func PostRequest(url string, keyBasic string, postBody io.Reader, flag int, _proxy string) ([]byte, int, error) {
	availableCode := []int{200, 201, 203}
	var (
		client *http.Client
		err    error
	)
	client, err = proxyResolution(_proxy)
	req, err := http.NewRequest(http.MethodPost, url, postBody)
	if err != nil {
		return nil, 0, ErrorSimpleHandler(err, "Cannot create request.")
	}

	req.Header.Add("Authorization", keyBasic)
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:87.0) Gecko/20100101 Firefox/87.0")
	if flag == 2 {
		req.Header.Add("Origin", "file://")
		req.Header.Add("Sec-Fetch-Site", "cross-site")
		req.Header.Add("Sec-Fetch-Mode", "cors")
	} else if flag == 3 {
		req.Header.Add("MyService-version", "1.0.0")
		req.Header.Add("MyService-client", "MyService")
		req.Header.Add(
			"MyService-mnemonic",
			"system suffer adult pass dad onion stage cheese sea yellow crack skirt winter bread impact donate shock obvious can loyal input urban hand busy",
		)
		req.Header.Set(
			"UserEmail-Agent",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36",
		)
		req.Header.Add("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryptvNIQBMvgs0MlgC")
		req.Header.Add("Origin", "https://MyService.com")
		req.Header.Add("Sec-Fetch-Site", "same-origin")
		req.Header.Add("Sec-Fetch-Mode", "cors")
		req.Header.Add("Sec-Fetch-Dest", "empty")
		req.Header.Add("Referer", "https://MyService.com/app")
	} else {
		req.Header.Add("User-Agent", "MyService")
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, ErrorSimpleHandler(err, "Cannot do request.")
	}
	// check server's error and repeat if server response error
	if resp.StatusCode > 500 {
		return nil, resp.StatusCode, ErrorSimpleHandler(err, "Server's error response, try again.")
	}
	body, err := ioutil.ReadAll(resp.Body)
	checkCode := contains(availableCode, resp.StatusCode)
	if err != nil || checkCode == false {
		return nil, 0, ErrorResponse(err, url, "Wrong answer", resp.StatusCode)
	}
	return body, resp.StatusCode, nil
}

/*
	GetRequest function takes as input a URL, "Basic" authentication, a flag (depending on the destination:
	host or bridge), and a proxy server credentials in "0.0.0.0@user:pass" format. Returns the body of the GET request in
	bytes, the status of the response code, and the error, if any.
*/
func GetRequest(url, KeyBasic string, flag int, _proxy string) ([]byte, int, error) {
	var (
		client *http.Client
		err    error
	)
	client, err = proxyResolution(_proxy)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, 0, errors.Wrapf(err, "\nError connect with %v, %v", url, req)
	}
	if flag == 1 {
		req.Header.Add("UserEmail-Agent", "MyService")
		req.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:87.0) Gecko/20100101 Firefox/87.0")
		req.Header.Add(http.CanonicalHeaderKey("MyService-node-id"), KeyBasic)
	} else if flag == 0 {
		req.Header.Add("Authorization", KeyBasic)
		req.Header.Add("UserEmail-Agent", "MyService")
		req.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:87.0) Gecko/20100101 Firefox/87.0")
		req.Header.Add("Accept", `*/*`)
		req.Header.Add("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, errors.Wrapf(err, "\nBad request to %v", url)
	}
	// check server's error and repeat if server response error
	if resp.StatusCode > 500 {
		return nil, resp.StatusCode, ErrorSimpleHandler(err, "Server's error response, try again.")
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return nil, resp.StatusCode, ErrorResponse(err, url, "", resp.StatusCode)
	}
	return body, resp.StatusCode, nil
}

/*
	proxyResolution resolve transport through proxy server passed in argument.
	Return new client for any request.
*/
func proxyResolution(_proxy string) (*http.Client, error) {
	var (
		client *http.Client
		dialer proxy.Dialer
	)

	if _proxy != "" {
		checkProxy, err := regexp.MatchString("@", _proxy)
		if checkProxy {
			authAndAddress := strings.Split(_proxy, "@")
			auth := authAndAddress[0]
			andAddress := authAndAddress[1]
			userPassProxy := strings.Split(auth, ":")
			userProxy := userPassProxy[0]
			passwordProxy := userPassProxy[1]
			authData := proxy.Auth{
				User:     userProxy,
				Password: passwordProxy,
			}
			dialer, err = proxy.SOCKS5("tcp", andAddress, &authData, proxy.Direct)
			if err != nil {
				return nil, err
			}
			client = &http.Client{
				Transport: &http.Transport{
					Dial: dialer.Dial,
				},
			}
		} else {
			dialer, err = proxy.SOCKS5("tcp", _proxy, nil, proxy.Direct)
			if err != nil {
				return nil, err
			}
			client = &http.Client{
				Transport: &http.Transport{
					Dial: dialer.Dial,
				},
			}
		}
	} else {
		client = new(http.Client)
	}
	return client, nil
}

/*
	The rest of the code is hidden.
*/
