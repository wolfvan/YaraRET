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
	//	"encoding/gob"
	//	"net"
	"bufio"
	"github.com/radare/r2pipe-go"
	"log"
	"os"
	"regexp"
	"strconv"
)

func searchOpenIOCCmd2(rawdisk string, openioc string){
	var tmpsliceIOC []newResult

	var ips []string
	var domains []string
	var index int
	//var rule string

	ips = parseIP(openioc)


	f, err := os.Create(workspace + "/rule_openioc.yar")
	if err != nil {
		panic(err)
	}
	defer f.Close()
	for _, elem := range ips {
		index = index + 1

		file, err := os.OpenFile(workspace+"/rule_openioc.yar", os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.Fatalf("failed opening file: %s", err)
		}
		defer file.Close()

		len, err := file.WriteString("rule ip_" + strconv.Itoa(index) + ": IP\n{\n\tmeta:\n\t\tauthor = \"Joan Soriano\"\n\n\tstrings:\n\t\t$a = \"" + elem + "\"\n\n\tcondition:\n\t\t$a\n} ")
		if err != nil {
			log.Fatalf("failed writing to file: %s", err)
			fmt.Println(len)
		}

		iocStruct := ioc{rule: "ip_" + strconv.Itoa(index), Data: elem, OffsetHeader: 0, match: false, indexMatch: 0, domain: false}
		sliceIOC = append(sliceIOC, iocStruct)

	}

	domains = parseDomains(openioc)


	for _, elem := range domains {
		index = index + 1

		file, err := os.OpenFile(workspace+"/rule_openioc.yar", os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.Fatalf("failed opening file: %s", err)
		}
		defer file.Close()

		len, err := file.WriteString("rule domain_" + strconv.Itoa(index) + ": DOMAIN\n{\n\tmeta:\n\t\tauthor = \"Joan Soriano\"\n\n\tstrings:\n\t\t$a = \"" + elem + "\"\n\n\tcondition:\n\t\t$a\n} ")
		if err != nil {
			log.Fatalf("failed writing to file: %s", err)
			fmt.Println(len)
		}

		iocStruct := ioc{rule: "domain_" + strconv.Itoa(index), Data: elem, OffsetHeader: 0, match: false, indexMatch: 0, domain: true}
		sliceIOC = append(sliceIOC, iocStruct)
	}



	resultsToT := searchYara(rawdisk, "./rule_openioc.yar")
	fmt.Println("[+] " + strconv.Itoa(len(resultsToT)) + " match found")


	for _, elem:= range sliceSet{
		flagg := false
		for _, elem2 := range resultsToT{
			if elem2.offset < elem.OffsetFooter && elem2.offset > elem.OffsetHeader{
				fmt.Println("[+] Match "+string(elem2.Data)+" in "+elem.Rule+"_"+strconv.Itoa(elem.Index))
				resultStruct := newResult{Rule: elem.Rule, OffsetHeader: elem.OffsetHeader, OffsetFooter: elem.OffsetFooter, Data: elem.Data, Yara: elem.Yara, Ioc: string(elem.Data[:]), Index: elem.Index, Hash: elem.Hash, Size: elem.Size}
				tmpsliceIOC = append(tmpsliceIOC, resultStruct)
				flagg = true
			}	
		if flagg == false{			
			resultStruct := newResult{Rule: elem.Rule, OffsetHeader: elem.OffsetHeader, OffsetFooter: elem.OffsetFooter, Data: elem.Data, Yara: elem.Yara, Ioc: elem.Ioc, Index: elem.Index, Hash: elem.Hash, Size: elem.Size}
			tmpsliceIOC = append(tmpsliceIOC, resultStruct)			
		}					
		}
	}
	sliceSet = tmpsliceIOC


}


func searchOpenIOCCmd(rawdisk string, openioc string, maxsize string, filetype string) {
	var ips []string
	var domains []string
	var index int
	//var rule string
	//var mylastheader uint64

	ips = parseIP(openioc)

	if xor == true {
		ips = appendXORioc(ips)
	}
	f, err := os.Create(workspace + "/rule_openioc.yar")
	if err != nil {
		panic(err)
	}
	defer f.Close()
	for _, elem := range ips {
		index = index + 1

		file, err := os.OpenFile(workspace+"/rule_openioc.yar", os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.Fatalf("failed opening file: %s", err)
		}
		defer file.Close()

		len, err := file.WriteString("rule ip_" + strconv.Itoa(index) + ": IP\n{\n\tmeta:\n\t\tauthor = \"Joan Soriano\"\n\n\tstrings:\n\t\t$a = \"" + elem + "\"\n\n\tcondition:\n\t\t$a\n} ")
		if err != nil {
			log.Fatalf("failed writing to file: %s", err)
			fmt.Println(len)
		}

		iocStruct := ioc{rule: "ip_" + strconv.Itoa(index), Data: elem, OffsetHeader: 0, match: false, indexMatch: 0, domain: false}
		sliceIOC = append(sliceIOC, iocStruct)

	}

	domains = parseDomains(openioc)
	if xor == true {
		domains = appendXORioc(domains)
	}

	for _, elem := range domains {
		index = index + 1

		file, err := os.OpenFile(workspace+"/rule_openioc.yar", os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.Fatalf("failed opening file: %s", err)
		}
		defer file.Close()

		len, err := file.WriteString("rule domain_" + strconv.Itoa(index) + ": DOMAIN\n{\n\tmeta:\n\t\tauthor = \"Joan Soriano\"\n\n\tstrings:\n\t\t$a = \"" + elem + "\"\n\n\tcondition:\n\t\t$a\n} ")
		if err != nil {
			log.Fatalf("failed writing to file: %s", err)
			fmt.Println(len)
		}

		iocStruct := ioc{rule: "domain_" + strconv.Itoa(index), Data: elem, OffsetHeader: 0, match: false, indexMatch: 0, domain: true}
		sliceIOC = append(sliceIOC, iocStruct)
	}



		extractFromYara(rawdisk, "./rule_openioc.yar", maxsize, filetype)

}

func printSliceIOC(matchIOC []result) {

	for _, elem := range matchIOC {

		fmt.Println("[+] Match!")
		fmt.Println("\t[-] File:" + elem.rule)
		fmt.Println("\t[-] IoC:" + string(elem.Data[:]))
		fmt.Println("\t[-] Offset:" + strconv.Itoa(int(elem.offset)) + "\n")

	}
}

func updateMatchIOC(resultsIOC []result) {

	//sliceIOC = []
	var tmpsliceIOC []ioc

	//tmpsliceIOC := sliceIOC
	//fmt.Println(resultsIOC)
	//fmt.Println(sliceIOC)
	//sliceIOC = nil

	for _, elem := range resultsIOC {
		for _, elem1 := range sliceIOC {
			if elem.rule == elem1.rule {
				//fmt.Println("hiii")
				iocStruct := ioc{rule: elem1.rule, Data: elem1.Data, OffsetHeader: elem.offset, match: true, indexMatch: 1, domain: elem1.domain}
				//fmt.Println(iocStruct)
				tmpsliceIOC = append(tmpsliceIOC, iocStruct)
			}
		}
	}
	sliceIOC = tmpsliceIOC
	//fmt.Println(sliceIOC)

}

func updateResultsIOC() {

	//sliceIOC = []
	var tmpsliceIOC []newResult
	//fmt.Print(sliceNewResults)
	//fmt.Println(sliceIOC)
	//tmpsliceIOC := sliceIOC
	//fmt.Println(resultsIOC)
	//fmt.Println(sliceIOC)
	//sliceIOC = nil

	for _, elem := range sliceIOC {
		for _, elem1 := range sliceNewResults {
			if elem.OffsetHeader > elem1.OffsetHeader && elem.OffsetHeader < elem1.OffsetFooter {
				resultStruct := newResult{Rule: elem1.Rule, OffsetHeader: elem1.OffsetHeader, OffsetFooter: elem1.OffsetFooter, Data: elem1.Data, Yara: elem1.Yara, Ioc: elem.Data, Index: elem1.Index, Hash: elem1.Hash, Size: elem1.Size}
				tmpsliceIOC = append(tmpsliceIOC, resultStruct)
			}
		}
	}

	//printStructure(sliceNewResults)
	//fmt.Println(sliceNewResults)

}

func parseIP(openioc string) []string {

	var ips []string

	regex := regexp.MustCompile(`(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}`)

	//fmt.Printf("Pattern: %v\n", re.String()) // print pattern
	//fmt.Println(re.MatchString(str1)) // true

	// submatchall := re.FindAllString(str1, -1)
	// for _, element := range submatchall {
	//     fmt.Println(element)
	// }

	file, err := os.Open(openioc)
	if err != nil {
		fmt.Println(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	// This is our buffer now
	var lines []string

	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	//fmt.Println("read lines:")
	for _, line := range lines {
		if regex.MatchString(line) {
			submatchall := regex.FindAllString(line, -1)
			for _, element := range submatchall {
				//fmt.Println(element)
				ips = append(ips, element)
				//fmt.Printf("%s\n", string(buf))
			}
		}
		//fmt.Println(line)
	}

	//    fh, err := os.Open(file)
	//    f := bufio.NewReader(fh)

	//    if err != nil {
	// 	fmt.Print("error")
	//    }
	//    defer fh.Close()

	//    buf := make([]byte, 1024)
	//    for {
	// 	buf, _ , err = f.ReadLine()
	// 	if err != nil {
	// 		fmt.Print("error")
	// 	}

	// 	s := string(buf)
	// 	if regex.MatchString(s) {
	// 		ips = append(ips,s)
	// 		fmt.Printf("%s\n", string(buf))
	// 	}
	// }
	//var ips = []string{"pe","elf64"}
	//fmt.Println(ips)
	return ips
}

func parseDomains(openioc string) []string {

	var domains []string

	regex := regexp.MustCompile(`^(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|([a-zA-Z0-9][a-zA-Z0-9-_]{1,61}[a-zA-Z0-9]))\.([a-zA-Z]{2,6}|[a-zA-Z0-9-]{2,30}\.[a-zA-Z
 ]{2,3})$`)

	//fmt.Printf("Pattern: %v\n", re.String()) // print pattern
	//fmt.Println(re.MatchString(str1)) // true

	// submatchall := re.FindAllString(str1, -1)
	// for _, element := range submatchall {
	//     fmt.Println(element)
	// }

	file, err := os.Open(openioc)
	if err != nil {
		fmt.Println(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	// This is our buffer now
	var lines []string

	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	//fmt.Println("read lines:")
	for _, line := range lines {
		if regex.MatchString(line) {
			submatchall := regex.FindAllString(line, -1)
			for _, element := range submatchall {
				//fmt.Println(element)
				domains = append(domains, element)
				//fmt.Printf("%s\n", string(buf))
			}
		}
		//fmt.Println(line)
	}

	//    fh, err := os.Open(file)
	//    f := bufio.NewReader(fh)

	//    if err != nil {
	// 	fmt.Print("error")
	//    }
	//    defer fh.Close()

	//    buf := make([]byte, 1024)
	//    for {
	// 	buf, _ , err = f.ReadLine()
	// 	if err != nil {
	// 		fmt.Print("error")
	// 	}

	// 	s := string(buf)
	// 	if regex.MatchString(s) {
	// 		ips = append(ips,s)
	// 		fmt.Printf("%s\n", string(buf))
	// 	}
	// }
	//var ips = []string{"pe","elf64"}
	//fmt.Println(ips)
	return domains
}

func appendXORioc(ioc []string) []string {

	var tmpXor []string

	for _, elem := range ioc {

		r2p, err := r2pipe.NewPipe("-")
		if err != nil {
			print("ERROR: ", err)
		}
		defer r2p.Close()

		disasm, err := r2p.Cmd("oo+")
		if err != nil {
			print("ERROR: ", err)
		} else {
			print(disasm, "")
		}

		disasm, err = r2p.Cmd("w " + elem)
		if err != nil {
			print("ERROR: ", err)
		} else {
			print(disasm, "")
		}

		disasm, err = r2p.Cmd("b " + strconv.Itoa(len(elem)))
		if err != nil {
			print("ERROR: ", err)
		} else {
			print(disasm, "")
		}

		for i := 1; i < 90; i++ {
			if i < 10 {
				disasm, err = r2p.Cmd("wox 0x0" + strconv.Itoa(i))
				if err != nil {
					print("ERROR: ", err)
				} else {
					print(disasm, "")
				}

			} else {
				disasm, err = r2p.Cmd("wox 0x" + strconv.Itoa(i))
				if err != nil {
					print("ERROR: ", err)
				} else {
					print(disasm, "")
				}
			}

			disasm2, err := r2p.Cmd("ps")
			if err != nil {
				print("ERROR: ", err)
			} else {
				print(disasm, "")
			}
			if stringInSlice(disasm2, tmpXor) == false {
				if len(disasm2) == len(elem) {
					tmpXor = append(tmpXor, disasm2)
				}
			}

		}

	}

	for _, elem := range tmpXor {
		ioc = append(ioc, elem)
	}

	return ioc
}
