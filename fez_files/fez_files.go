package main //fez_files

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/FEZ-DMS/fez_lib/fez_hash"
)

type _filemodes struct {
	PUBLIC_RW, PUBLIC_RWX, USER_RW, USER_RWX, GROUP_AND_USER_RW, GROUP_AND_USER_RWX os.FileMode
}

var FILEMODES = _filemodes{
	PUBLIC_RW:          0666,
	PUBLIC_RWX:         0777,
	USER_RW:            0600,
	USER_RWX:           0700,
	GROUP_AND_USER_RW:  0660,
	GROUP_AND_USER_RWX: 0770,
}

func DoesFileExist(path string) bool {
	_, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false
	}
	return true
}

func DoesDirExist(path string) bool {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false
	} else if info.IsDir() {
		return true
	} else {
		return false
	}
}

type RelativeIndexedFile struct {
	Name        string
	ChecksumHex string
}

type AbsoluteIndexedFile struct {
	Name        string
	ChecksumHex string
}

type RelativeDirectoryIndex struct {
	Name           string
	Subdirectories []RelativeDirectoryIndex
	Files          []RelativeIndexedFile
}

func (self *RelativeDirectoryIndex) Convert() AbsoluteDirectoryIndex {
	var files []AbsoluteIndexedFile
	for _, file := range self.Files {
		files = append(files, AbsoluteIndexedFile{
			Name:        self.Name + "/" + file.Name,
			ChecksumHex: file.ChecksumHex,
		})
	}

	var subdirs []AbsoluteDirectoryIndex
	for _, dir := range self.Subdirectories {
		dir.Name = self.Name + "/" + dir.Name
		newdir := dir.Convert()
		subdirs = append(subdirs, newdir)
	}
	return AbsoluteDirectoryIndex{
		Name:           self.Name,
		Subdirectories: subdirs,
		Files:          files,
	}
}

type AbsoluteDirectoryIndex struct {
	Name           string
	Subdirectories []AbsoluteDirectoryIndex
	Files          []AbsoluteIndexedFile
}

func (self *AbsoluteDirectoryIndex) Encode() (string, error) {
	str := self.Name + "/\n"
	for _, file := range self.Files {
		str = str + file.Name + " >> " + file.ChecksumHex + "\n"
	}
	for _, dir := range self.Subdirectories {
		dirstr, err := dir.Encode()
		if err != nil {
			return "", err
		}
		str = str + "\n" + dirstr
	}

	return str, nil
}

func MakeTree(directory_path string, calculate_checksum bool) (RelativeDirectoryIndex, error) {
	if !strings.HasSuffix(directory_path, "/") {
		directory_path = directory_path + "/"
	}
	if !DoesDirExist(directory_path) {
		return RelativeDirectoryIndex{}, os.ErrNotExist
	}
	root := RelativeDirectoryIndex{
		Name: filepath.Base(directory_path),
	}
	var subdirs []RelativeDirectoryIndex
	var files []RelativeIndexedFile
	direntry, err := os.ReadDir(directory_path)
	if err != nil {
		return RelativeDirectoryIndex{}, err
	}
	for _, entry := range direntry {
		if entry.IsDir() {
			treesub, err := MakeTree(directory_path+entry.Name(), calculate_checksum)
			if err != nil {
				return RelativeDirectoryIndex{}, err
			}
			subdirs = append(subdirs, treesub)
		} else {
			chksm := ""
			if calculate_checksum {
				data, err := os.ReadFile(directory_path + entry.Name())
				if err != nil {
					return RelativeDirectoryIndex{}, err
				}
				h := fez_hash.XXH64Hash{}
				h.Set(data)
				chksm = h.Hex
			}
			file := RelativeIndexedFile{
				Name:        entry.Name(),
				ChecksumHex: chksm,
			}
			files = append(files, file)
		}
	}
	root.Subdirectories = subdirs
	root.Files = files

	return root, nil
}

func main() {
	fmt.Println("TEST")
	thetre, err := MakeTree(filepath.Join(".", "testdir"), true)
	if err != nil {
		log.Fatal(err)
	}
	fn := thetre.Convert()
	fmt.Println(fn.Encode())
	fmt.Println("TEST END")
}
