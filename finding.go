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
	// "fmt"
	// //      "encoding/gob"
	yara "github.com/hillu/go-yara"	
	// //      "net"
	// "github.com/radare/r2pipe-go"
	// "net/url"
	// "flag"
	// "encoding/json"
	// "log"
 //        "github.com/dutchcoders/go-virustotal"
	// "io/ioutil"
	//"strconv"
	// "strings"
	// "os"
)

func findAllData(rawdisk string)[]result{


	var v []result

	supported := []string{"threegp","sevenzip","amazonkindleupdate","appleworks5","appleworks6","avi","bmp","bzip","canonraw","crx","dalvik","dat","dba","deb","dmg","doc","elf64","flac","flash","gif","gzip","is","javaclass","jpg","kodakcineon","macho","microsoftOffice","midi","mkv","mp3","mpeg","ost","pcap","pcapng","pdf","pe","png","pds","pst","pyc","rar","rpm","rtf","tape","tar","tarzip","tiff","utf8","vmdk","wasm","wav","woff","xar","xml","xz","zip","zlib"}


	for _, elem1 := range supported{
	//count := count+1
		comp, err := yara.NewCompiler()
		if err != nil {
			fmt.Println(err)
		}
		body := returnBody(elem1)
		condition := returnConditionOnly()
		rule := body+condition	
		//rule := buildRule("0", "0", elem1)
		comp.AddString(rule, "")
	//fmt.Println(rule)
	rules, err := comp.GetRules()
	if err != nil {
		fmt.Println(err)
	}
	matches, err := rules.ScanFile(rawdisk, 0, 0)
	for _, matches := range matches {
		for _, stringf := range matches.Strings {
			s := result{rule: matches.Rule, offset: stringf.Offset, Data: stringf.Data}
			v = append(v, s)
			//fmt.Println(s)
			//fmt.Println("[+] Match! "+s.rule)
		}
	}
}
	//fmt.Println(v)
	return v
}

func findOneData(rawdisk string, filetype string)[]result{

	//for initialize only one filetype
	var v []result



	comp, err := yara.NewCompiler()
	if err != nil {
		fmt.Println(err)
	}
	body := returnBody(filetype)

	condition := returnConditionOnly()
	rule := body+condition	
		//rule := buildRule("0", "0", elem1)
	comp.AddString(rule, "")
	//fmt.Println(rule)
	rules, err := comp.GetRules()
	if err != nil {
		fmt.Println(err)
	}
	matches, err := rules.ScanFile(rawdisk, 0, 0)
	for _, matches := range matches {
		for _, stringf := range matches.Strings {
			s := result{rule: matches.Rule, offset: stringf.Offset, Data: stringf.Data}
			v = append(v, s)
			//fmt.Println(s)
			//fmt.Println("[+] Match! "+s.rule)
		}
	}
	//fmt.Println(v)
	return v
}





func returnConditionOnly()string{
	condition :=`condition:		        
	$a
}
`	
	return condition
}