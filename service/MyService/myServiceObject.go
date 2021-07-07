// Package myService developed to demonstrate the style of writing code to the employer.
// This library implements mechanisms for manipulating objects in the decentralized cloud storage.
package myService

import (
	"encoding/json"
	"fmt"
	"goprojects/cloud/service"
	"io/ioutil"
	"math"
	"os"
	"strconv"
	"strings"
)

const (
	ErrRemove  = "Download error\nCannot remove temporary files"
	ErrRequest = "Download error\nBad request"
	ErrWrite   = "Download error\nCan't write temporary file\n"
)

// MyServiceObject implement general fields for objects manipulation
type MyServiceObject struct {
	ParentService   *MyService
	Parent          *service.ServiceObject
	Id              string
	Name            string
	Path            string
	Size            string
	Created         string
	ParentID        string
	ApiId           string
	IsDir           bool
	IsFile          bool
	IsBucket        bool
	someConditional bool
}

func (ms *MyServiceObject) ReturnId() string {
	if ms.someConditional {
		return ms.ApiId
	}
	return ms.Id + ";" + ms.ApiId
}

func (ms *MyServiceObject) File() bool {
	return ms.IsFile
}

func (ms *MyServiceObject) SomeBool() bool {
	return ms.someConditional
}

func (ms *MyServiceObject) Dir() bool {
	return ms.IsDir
}

func (ms *MyServiceObject) ReturnName() string {
	return ms.Name
}

func (ms *MyServiceObject) GetParent() *service.ServiceObject {
	return ms.Parent
}

func (ms *MyServiceObject) SetParent(object *service.ServiceObject) {
	ms.Parent = object
}

func (ms *MyServiceObject) ReturnPath() string {
	return ms.Path
}

func (ms *MyServiceObject) ReturnSize() int {
	size, err := strconv.Atoi(ms.Size)
	if err != nil {
		return 0
	}
	return size
}

// Download function implement download object to local space
func (ms *MyServiceObject) Download(path string) error {
	var (
		totalDataShards   int
		totalParityShards int
		size              int
		missingShards     int
		realParseShards   int
		tmpFile           string
		tmpFolder         string
		newDir            string
		URL               string
		_proxy            string
		basicKey          string
		mnemonic          string
		fileId            string
		bucketId          string
		opSys             string
	)

	opSys = ms.ParentService.system.OperationSystem // get operation user's system
	fmt.Printf("\n[DEBUG] Start download function\n[DEBUG] %s was detected\n", opSys)
	// conditionals for download from bucket (root directory)
	// and create directory with service's name where new files will be download
	if ms.Name == "/" && opSys == "windows" {
		fmt.Println("\n[DEBUG] Start download all function")
		pathInfo, err := os.Stat(path) // use for get user's directory permissions
		if pathInfo == nil {
			err = directoryHandlerChecker(pathInfo, path) // if path doesn't exist -- create this path
			if err != nil {
				return ErrorMkdir(err, path)
			}
		}
		// start create directory with service name
		path = path + "\\" + "MyService"
		fmt.Println("[DEBUG] Creating main directory...")
		err = os.MkdirAll(path, pathInfo.Mode())
		if err != nil {
			return ErrorMkdir(err, path)
		}
		fmt.Printf("[DEBUG] Path %s was created\n", path)
	} else if ms.Name == "/" && opSys != "windows" {
		return nil
	}

	// check object type
	// this condition is responsible for downloading all files in the directory
	if ms.IsDir || ms.IsBucket {
		fmt.Printf("[DEBUG] Storage directory '%s' was detected for creating in file system\n", ms.Name)
		// declare path for download directory
		newPath := path + "\\" + ms.Name
		// convert a path based on the operating system
		if ms.ParentService.system.OperationSystem == "windows" {
			newDir = newPath
		} else {
			newDir = strings.Replace(newPath, "\\", "/", -1)
		}
		// get path information for get user's permissions
		pathInfo, err := os.Stat(path)
		if pathInfo == nil {
			err = directoryHandlerChecker(pathInfo, path) // if path doesn't exist -- create this path
			if err != nil {
				return ErrorMkdir(err, path)
			}
		}
		check, err := os.Stat(newDir)
		if check == nil {
			err = directoryHandlerChecker(check, newDir)
			if err != nil {
				return ErrorMkdir(err, newDir)
			}
		}
		err = os.MkdirAll(newDir, pathInfo.Mode())
		if err != nil {
			err = ErrorMkdir(err, newDir)
		} else {
			fmt.Printf("[DEBUG] Directory %s was \n", ms.Name)
		}
		fmt.Printf("[DEBUG] Storage directory '%s' was created in file system\n[DEGUG] Full path: %s\n", ms.Name, newDir)
		// list all objects in directory for download
		obj, _ := ms.ParentService.ListObjects(ms)
		objCounter := len(obj)
		for _, o := range obj {
			objCounter--
			// star download each object in directory
			err = o.Download(newDir)
			if err != nil {
				if objCounter == 0 {
					return ErrorSimpleHandler(err, "Download error\nWrong path: no one files were uploaded")
				}
				continue
			}
		}
	}

	// encryptionValue parse one of part encryption key
	type encryptionValue struct {
		DecryptionKeyPart string `json:"index"`
	}

	ev := &encryptionValue{}
	URL = GetURL()
	bucketId = ms.ParentService.Access.BucketID      // set storage ID
	basicKey = ms.ParentService.Access.BasicKey      // set key for basic authentication
	mnemonic = ms.ParentService.Access.MnemonicHuman // set mnemonic
	_proxy = ms.ParentService.Access.Proxy           // set proxy, empty value mean won't use proxy
	fileId = ms.ApiId                                // set ID file for Download

	if ms.IsFile {
		fmt.Println("[DEBUG] Start file download...")
		// get size for file
		if !ms.someConditional {
			size = ms.ReturnSize()
		} else {
			// if someConditional ON, get size from GetObjectInfo function
			objectInfo, err := ms.ParentService.GetObjectInfo(ms)
			if err != nil {
				return ErrorSimpleHandler(err, ErrRequest)
			}
			size = objectInfo.Size
		}
		fileName := ms.ReturnName()
		fmt.Println("[DEBUG] Return file name:", ms.Name)
		// distAddrInfo URL building for get information about file from server
		distAddrInfo := URL + "/path/" + bucketId + "/path/" + fileId + "/path"
		// getting info for decrypt about file from GET request and store into infoFile
		infoFile, code, err := GetRequest(distAddrInfo, basicKey, ToBridge, _proxy)
		if err != nil || code != 200 {
			fmt.Println("[ERROR] Download error: ", err)
			return err
		}
		fmt.Println("[DEBUG] File info was getting")
		// considering the operating system, we creating a temporary directory where
		// the encrypted parts of the file will be written
		if opSys == "windows" {
			tmpFolder = "C:\\Windows\\Temp\\MyService\\"
			err = os.Mkdir(tmpFolder, 0777)
			if err != nil {
				err = ErrorMkdir(err, newDir)
			}
			tmpFile = tmpFolder + fileName
		} else {
			fmt.Println("[NXI DEBUG] Checking folder to download file in file system")
			pathInfo, _ := os.Stat(path)
			if pathInfo == nil {
				err = directoryHandlerChecker(pathInfo, path)
				if err != nil {
					return ErrorMkdir(err, path)
				}
			} else {
				fmt.Printf("\n[NIX DEBUG] Not need to creating folder for download for path: %s\n", path)
			}
			tmpFolder = path + "/.MyService/"
			tmpChecker, _ := os.Stat(tmpFolder)
			if tmpChecker == nil {
				err = directoryHandlerChecker(pathInfo, tmpFolder)
				if err != nil {
					return ErrorMkdir(err, tmpFolder)
				}
			}
			fmt.Printf("[DEBUG] Path to tmp folder %s was created\n", tmpFolder)
			tmpFile = tmpFolder + fileName
		}
		// unmarshall a part of the decryption key
		err = json.Unmarshal(infoFile, &ev)
		if err != nil {
			return ErrorSimpleHandler(err, ErrRequest)
		}

		// starting calculating number of shards of file stored on hosts
		ShardSize := determineShardSize(size, 0, 0)
		totalDataShards = int(math.Ceil(float64(size) / float64(ShardSize)))
		if totalDataShards > 1 {
			totalParityShards = int(math.Ceil(float64(totalDataShards) * 2.0 / 3.0))
		}
		// get total number of shards, parity shards and real data shards
		totalShards := totalParityShards + totalDataShards
		fmt.Printf("\n[DEBUG] Total Shards: %d\n[DEBUG] With block size: %d bytes\n", totalShards, ShardSize)

		// DataDownloadForHosts describes the file data that must be obtained for uploading to the local machine.
		// Such as: file token, hash, parity (real data or parity data) and information about storage hosts
		type DataDownloadForHosts struct {
			Index     int    `json:"index"`
			Hash      string `json:"hash"`
			Size      int    `json:"size"`
			Parity    bool   `json:"parity"`
			Token     string `json:"token"`
			Farmer    `json:"farmer"`
			Operation string `json:"operation"`
		}

		type DataDownloadForHost struct {
			Data []*DataDownloadForHosts
		}

		rs := &DataDownloadForHost{}
		var dataDownload []byte
		// downloading struct needed for construct distinction address to each host
		type downloading struct {
			URL   []string
			HASH  []string
			NODE  []string
			INDEX []int
		}

		request := &downloading{}
		// this iteration needed to output three hosts at a time by one request from which files will be downloaded
		for i := 0; i < totalShards+1; i = i + 3 {
			if i == 0 {
				fmt.Println("[DEBUG] Start receiving information about shards")
			}
			// concat the address of the server from where the data about the hosts will be received
			distAddr := URL + "/path/" + bucketId + "/path/" + fileId + "?limit=3&skip=" + strconv.Itoa(i)
			// execute such a request
			responseBody, _, err := GetRequest(distAddr, basicKey, ToBridge, _proxy)
			if err != nil {
				return ErrorSimpleHandler(err, ErrRequest)
			}
			// store data into DataDownloadForHosts struct
			err = json.Unmarshal(responseBody, &rs.Data)
			// this iteration needed to group data for each host
			for _, getUrl := range rs.Data {
				if getUrl.Address == "" {
					fmt.Printf(
						"\n[DEBUG] Warning: server not to send host's address. File HASH: %s INDEX: %d", getUrl.Hash,
						getUrl.Index,
					)
					request.URL = append(request.URL, "")
					request.HASH = append(request.HASH, "")
					request.NODE = append(request.NODE, "")
					request.INDEX = append(request.INDEX, -1)
				} else {
					// concat destination host address
					distHost := "http://" + strings.TrimSpace(getUrl.Address) + ":" + strconv.Itoa(getUrl.Port) + "/shards/" + getUrl.Hash + "?token=" + getUrl.Token
					request.URL = append(request.URL, distHost)
					request.HASH = append(request.HASH, getUrl.Hash)
					request.NODE = append(request.NODE, getUrl.NodeID)
					request.INDEX = append(request.INDEX, getUrl.Index)
					// make counter for getting shards
					realParseShards++
					fmt.Printf("\n[DEBUG] Added address for shard's request list: %s", distHost)
				}
			}
			rs.Data = nil
		}
		// calculate missing shards during survey hosts
		missingShards = totalShards - realParseShards
		fmt.Println("\n[DEBUG] Missing shards number:", missingShards, "from", totalShards)
		// if there was no response to 30% of the fragments during the survey of hosts,
		// we ask you to repeat the download. Some hosts may be inactive.
		if missingShards < 0 || missingShards > totalParityShards {
			return ErrorSimpleHandler(err, "Download error\nOne of hosts cannot send data\ntry later")
		}
		// iterate through each host to download the shards
		for i := 0; i < totalShards; i++ {
			// GET-Request downloaded each shard from host
			dataDownload, _, err = GetRequest(request.URL[i], request.NODE[i], ToHost, _proxy)
			if err != nil {
				return ErrorSimpleHandler(err, "Download error\nOne of node can't response\ntry later")
			}
			// checking the integrity of the shard
			check := checkingHostData(dataDownload, request.HASH[i])
			if check == false {
				fmt.Printf("\n[DEBUG] HASH: %s does not match! Finding mirrors hosts.", request.HASH[i])
				// get number of available mirrors
				mirrorsCount, err := ms.ParentService.ListMirrors(
					fileId, URL, bucketId,
					basicKey, _proxy, request.HASH[i],
				)
				if err != nil {
					return ErrorSimpleHandler(
						err, "Download error\n\nOne of mirrors node can't response\ntry later",
					)
				}
				// set destination address for get information about mirrors. We added parameter "exclude=" to query and
				// going to iterate through argument of this parameter
				distAddrMirrors := fmt.Sprintf(
					"%s/path/%s/path/%s?limit=1&skip=%d&exclude=%s", URL, bucketId, fileId, request.INDEX[i],
					request.NODE[i],
				)
				// start iteration through number of mirrors
				for j := 0; j < mirrorsCount+1; j++ {
					if j == mirrorsCount+1 {
						// add missing shard in missing shards array if mirrors don't asking
						missingShards++
						break
					}
					// creating a structure for downloading from mirror hosts (described below)
					type MirrorFarmer struct {
						Port    int    `json:"port"`
						Address string `json:"address"`
						NodeID  string `json:"nodeID"`
					}

					type MirrorsHost struct {
						Hash         string `json:"hash"`
						Token        string `json:"token"`
						MirrorFarmer `json:"farmer"`
					}

					var mrr []MirrorsHost
					// get info about mirrors for download shards
					getMirrorsInfoFromBridge, _, err := GetRequest(distAddrMirrors, basicKey, ToBridge, _proxy)
					if err != nil {
						return err
					}
					err = json.Unmarshal(getMirrorsInfoFromBridge, &mrr)
					if mrr[0].Address != "" {
						// concat mirror host address for download
						distMirrorHost := "http://" + strings.TrimSpace(mrr[0].Address) + ":" + strconv.Itoa(mrr[0].Port) + "/path/" + request.HASH[i] + "?token=" + mrr[0].Token
						// make download request
						dataDownload, code, err = GetRequest(distMirrorHost, mrr[0].NodeID, ToHost, _proxy)
						if err != nil {
							return err
						}
						// checking the integrity of the shard
						check = checkingHostData(dataDownload, request.HASH[i])
						if check == false {
							// update distinction mirror address adding id of node through comma. Example of address:
							// http://MyService.com/path/path/path/path/path?limit=1&skip=2&exclude=NODE_ID, NODE_ID,...NODE_ID"
							distAddrMirrors = distAddrMirrors + "," + mrr[0].NodeID
						} else {
							break
						}
					}
				}
			}
			// check number of shards
			if totalShards > 1 {
				// for multi shards (downloaded file gre 2 MB) we store temporary file without indexing.
				// Note: indexing needed for recover file through reed solomon code
				err = ioutil.WriteFile(tmpFile, dataDownload, 0644)
				if err != nil {
					fmt.Println("[ERROR]", err)
					return ErrorSimpleHandler(err, ErrWrite)
				}
				fmt.Printf("[DEBUG] File %s was write for decrypting\n", tmpFile)
			} else if totalShards < 2 {
				// for single shard (downloaded file greater 2 MB) we make indexing temporary file.
				err = ioutil.WriteFile(tmpFile+"."+strconv.Itoa(i), dataDownload, 0644)
				fmt.Printf("[DEBUG] Shard number %d was write for file %s\n", i, tmpFile)
				if err != nil {
					return ErrorSimpleHandler(err, ErrWrite)
				}
			}
		}
		// check number of shards
		if totalShards > 1 {
			// perform reed solomon code for assemble shards to one file.
			err = ReedSolomonRecover(
				fileName, tmpFolder, totalDataShards,
				totalParityShards, size,
			)
			if err != nil {
				return ErrorSimpleHandler(err, "Download error\nCannot build file from shards")
			}
		}
		// decrypt data
		err = DecryptAES256ModeCTR(
			path, fileName, tmpFolder, mnemonic,
			bucketId, ev.DecryptionKeyPart,
		)
		// remove temporary folder
		err = os.RemoveAll(tmpFolder)
		if err != nil {
			return ErrorSimpleHandler(err, ErrRemove)
		}
		fmt.Println("\n[SUCCESS] Temporary files deleted!")
	}
	return nil
}

/*
	The rest of the code is hidden.
*/
