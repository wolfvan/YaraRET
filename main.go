/*
Open Source Initiative OSI - The MIT License (MIT):Licensing
The MIT License (MIT)
Copyright (c) 2013 DutchCoders <http://github.com/dutchcoders/>
Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package main

import (
	"fmt"
	"log"
	"os"
	docopt "github.com/docopt/docopt-go"
)



var rawdisk string

var totIndex string

var verbose bool

var OutputFile = ""

var vtiAPI = ""

var historyFile = ""

var totrawdisk string

var footersupport []string

var headersupport []string

var maxSizeDump = "50000"

var maxsize string

var filetype string

var dataSelected string

var xor bool

var workspace string

var supported = []string{"threegp","sevenzip","amazonkindleupdate","appleworks5","appleworks6","avi","bmp","bzip","canonraw","crx","dalvik","dat","dba","deb","dmg","doc","elf64","flac","flash","gif","gzip","is","javaclass","jpg","kodakcineon","macho","microsoftOffice","midi","mkv","mp3","mpeg","ost","pcap","pcapng","pdf","pe","png","pds","pst","pyc","rar","rpm","rtf","tape","tar","tarzip","tiff","utf8","vmdk","wasm","wav","woff","xar","xml","xz","zip","zlib"}

var hashlist []string

type newResult1 struct {
	Rule string
}

var resultsMagicINIT []result


type ioc struct {
	rule         string
	Data         string
	OffsetHeader uint64
	match        bool
	indexMatch   int
	domain       bool
}

type ssdeepSlice struct {
	Name   string
	Ssdeep string
}

type stats struct {
	rule  string
	total int
}

type unMarshal struct {
	newresult newResult
}

var Footer string

var sliceIOC []ioc
var sliceIOCmatched []ioc

type newResult struct {
	Rule         string   `json:"Rule"`
	OffsetHeader uint64   `json:"OffsetHeader"`
	OffsetFooter uint64   `json:"OffsetFooter"`
	Data         []byte   `json:"Data"`
	Yara         []string `json:"Yara"`
	Ioc          string   `json:"Ioc"`
	Index        int      `json:"Index"`
	Ssdeep       string   `json:"Ssdeep"`
	Hash         string   `json:"Hash"`
	Size         uint64   `json:"Size"`
	Comment      string   `json:"Comment"`
	Tag          string   `json:"Tag"`
	Entropy      int64    `json:"Entropy"`
}

var sliceNewResults []newResult

var sliceSet []newResult


var magicPath string = "./magicrules/"

func main() {

	usage := `YaraRET - Carving binaries with Yara & Radare.

Usage:
  yararet rawdisk <rawdisk> yarafile <yarafile> maxsize <maxsize>
  yararet rawdisk <rawdisk> ioc <ioc>
  yararet rawdisk <rawdisk> ioc <ioc> maxsize <maxsize> [ --xor]
  yararet rawdisk <rawdisk> hash <hash> filetype <filetype> [ --sections ] [ --vti ]
  yararet rawdisk <rawdisk> ioc <ioc> maxsize <maxsize> filetype <filetype> [ --xor]
  yararet -h | --help
  yararet rawdisk <rawdisk> shell
  yararet --version

Options:
  -h --help             Show this screen.
  -s --shell            Runs interactive shell

`
	version := "1.0"
	arguments, _ := docopt.Parse(usage, nil, true, version, false)
	totrawdisk = arguments["<rawdisk>"].(string)
	fmt.Println("\n\n██╗   ██╗ █████╗ ██████╗  █████╗ ██████╗ ███████╗████████╗\n╚██╗ ██╔╝██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔════╝╚══██╔══╝\n ╚████╔╝ ███████║██████╔╝███████║██████╔╝█████╗     ██║   \n  ╚██╔╝  ██╔══██║██╔══██╗██╔══██║██╔══██╗██╔══╝     ██║   \n   ██║   ██║  ██║██║  ██║██║  ██║██║  ██║███████╗   ██║   \n   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝   ╚═╝\n\n")

	dir, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	workspace = dir

	if arguments["shell"].(bool) {
		rawdisk := arguments["<rawdisk>"].(string)
		runShell(rawdisk)
	}

	if arguments["hash"].(bool) {
		rawdisk := arguments["<rawdisk>"].(string)
		filetype = arguments["<filetype>"].(string)
		hashes := arguments["<hash>"].(string)
		runHash(rawdisk, filetype, hashes)
	}

	if arguments["ioc"].(bool) {
		rawdisk := arguments["<rawdisk>"].(string)
		maxsize = arguments["<maxsize>"].(string)
		ioc := arguments["<ioc>"].(string)
		//filetype = arguments["<filetype>"].(string)
		xor = arguments["--xor"].(bool)
		filetype := "pyc"
		searchOpenIOCCmd(rawdisk, ioc, maxsize, filetype)
	}

	if arguments["yarafile"].(bool) {
			rawdisk := arguments["<rawdisk>"].(string)
			yarafile := arguments["<yarafile>"].(string)
			maxsize = arguments["<maxsize>"].(string)
			//filetype = arguments["<filetype>"].(string)
			//filetype = arguments["<filetype>"].(string)
			extractFromYara(rawdisk, yarafile, maxsize, filetype)
		}
}