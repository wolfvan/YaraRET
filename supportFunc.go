/*
Open Source Initiative OSI - The MIT License (MIT):Licensing
The MIT License (MIT)
Copyright (c) 2013 DutchCoders <http:
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
	"time"
	"debug/pe"
	
	
	"github.com/radare/r2pipe-go"
	"io/ioutil"
	"strconv"
	"strings"
	"os"
)

var a string


func intInSlice(a int, list []int) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}


func getHexFromString(hex string) uint64{

 	cleaned := strings.Replace(hex, "0x", "", -1)

 	
 	result, _ := strconv.ParseUint(cleaned, 16, 64)
 	return uint64(result)

}




func generateNewResult(resultsHash []result) []newResult {

	var sliceNewResults []newResult
	var lastHeader result

	var index int
	for _, elem := range resultsHash {
		if strings.Contains(elem.rule, "header") {

			index += 1
			newR := newResult{Rule: strings.Split(elem.rule, "_")[0], OffsetHeader: elem.offset, OffsetFooter: 0, Data: elem.Data, Index: index}
			sliceNewResults = append(sliceNewResults, newR)

			
			
			
			
			
			
			lastHeader = elem

		} else {
			if strings.Contains(elem.rule, "footer") {
				thisFiletype := strings.Split(elem.rule, "_")[0]
				lastFiletype := strings.Split(lastHeader.rule, "_")[0]

				if thisFiletype == lastFiletype {
					if len(strconv.Itoa(int(elem.offset))) > 2 {
						index += 1

						newR := newResult{Rule: strings.Split(elem.rule, "_")[0], OffsetHeader: lastHeader.offset, OffsetFooter: elem.offset, Data: elem.Data, Index: index, Size: (elem.offset - lastHeader.offset)}
						
						sliceNewResults = append(sliceNewResults, newR)
					}					
				}

			}
		}

	}

	return sliceNewResults
}

func generateNewResultYaraForensics(resultsHash []result) []newResult {

	var sliceNewResults []newResult

	var index int
	for _, elem := range resultsHash {

		index += 1
		newR := newResult{Rule: elem.rule, OffsetHeader: elem.offset, OffsetFooter: 0, Data: elem.Data, Index: index}
		sliceNewResults = append(sliceNewResults, newR)	

	}

	return sliceNewResults
}

func printStructure(structure []newResult) {

	for _, elem := range structure {

		fmt.Println("File:" + elem.Rule)
		fmt.Println("\tIndex:" + strconv.Itoa(elem.Index))
		fmt.Println("\tOffset Header:" + strconv.Itoa(int(elem.OffsetHeader)))
		fmt.Println("\tOffset Footer:" + strconv.Itoa(int(elem.OffsetFooter)))
		fmt.Println("\n")
	}
}




func updateResultsYara(resultsYara []result) {
	var tmpsliceIOC []newResult
	var rulesIn []string
	
	for _, elem1 := range sliceSet {
		for _, elem := range resultsYara {
			if stringInSlice(elem.rule, rulesIn) == false {
				rulesIn = append(rulesIn, elem.rule)
				
			} else {

			}
		}

		resultStruct := newResult{Rule: elem1.Rule, OffsetHeader: elem1.OffsetHeader, OffsetFooter: elem1.OffsetFooter, Data: elem1.Data, Yara: rulesIn, Ioc: elem1.Ioc, Index: elem1.Index, Hash: a, Size: (elem1.OffsetFooter - elem1.OffsetHeader)}
		tmpsliceIOC = append(tmpsliceIOC, resultStruct)

	}
	
	

	
	sliceSet = tmpsliceIOC
	

}

func generateNewResultOpenIOC(resultsHash []result) []ioc {

	var sliceNewResults []newResult
	var newsliceIOC []ioc
	for _, elem := range resultsHash {
		for _, elem1 := range sliceIOC {
			if elem.rule == elem1.rule {
				
				
				elem1.OffsetHeader = elem.offset

				iocStruct := ioc{rule: elem1.rule, Data: elem1.Data, OffsetHeader: elem.offset, match: false, indexMatch: 0, domain: elem1.domain}
				newsliceIOC = append(newsliceIOC, iocStruct)

			}
		}
		fmt.Println(sliceNewResults)
	}
	
	
	

	
	
	

	sliceIOCmatched = newsliceIOC
	return sliceIOCmatched
}


func matchIOCfiletype() {
	for _, elem := range sliceNewResults {
		for _, elem1 := range sliceIOCmatched {
			if elem.Rule == elem1.rule {
				fmt.Println(elem.Rule)
			}
		}
	}
}

func setSlice(argument string) {
	var tmpslice []newResult
	rawdisk = totrawdisk
	for _, elem := range sliceSet {
		if argument == elem.Rule {
			resultStruct := newResult{Rule: elem.Rule, OffsetHeader: elem.OffsetHeader, OffsetFooter: elem.OffsetFooter, Data: elem.Data, Yara: elem.Yara, Ioc: elem.Ioc, Index: elem.Index, Size: (uint64(elem.OffsetFooter) - elem.OffsetHeader)}
			tmpslice = append(tmpslice, resultStruct)
		}

	}

	sliceSet = tmpslice
	
}

func setSliceYara(rule string) {
	var tmpslice []newResult

	for _, elem := range sliceSet {

		for _, elem1 := range elem.Yara {
			if rule == elem1 {
				resultStruct := newResult{Rule: elem.Rule, OffsetHeader: elem.OffsetHeader, OffsetFooter: elem.OffsetFooter, Data: elem.Data, Yara: elem.Yara, Ioc: elem.Ioc, Index: elem.Index, Size: elem.Size}
				tmpslice = append(tmpslice, resultStruct)
			}
		}

	}

	sliceSet = tmpslice
	
}

func setSliceEntropy(args []string) {
	var tmpslice []newResult


	valueEntropy, err := strconv.Atoi(args[1])
	if err != nil{
		fmt.Println(err)
	}
	if args[0] == ">"{
		for _, elem := range sliceSet {
				if int(elem.Entropy) > valueEntropy{
					resultStruct := newResult{Rule: elem.Rule, OffsetHeader: elem.OffsetHeader, OffsetFooter: elem.OffsetFooter, Data: elem.Data, Yara: elem.Yara, Ioc: elem.Ioc, Index: elem.Index, Size: elem.Size, Entropy:elem.Entropy}
					tmpslice = append(tmpslice, resultStruct)										
				}
				}
		
	}else{
		if args[0] == "<"{
			for _, elem := range sliceSet {
				if int(elem.Entropy) < valueEntropy{
					resultStruct := newResult{Rule: elem.Rule, OffsetHeader: elem.OffsetHeader, OffsetFooter: elem.OffsetFooter, Data: elem.Data, Yara: elem.Yara, Ioc: elem.Ioc, Index: elem.Index, Size: elem.Size, Entropy:elem.Entropy}
					tmpslice = append(tmpslice, resultStruct)										
				}
				}
		}
	}
	sliceSet = tmpslice
}



func unsetSliceYara(rule string) {
	var tmpslice []newResult
	for _, elem := range sliceSet {
		if stringInSlice(rule, elem.Yara) {
		} else {
			resultStruct := newResult{Rule: elem.Rule, OffsetHeader: elem.OffsetHeader, OffsetFooter: elem.OffsetFooter, Data: elem.Data, Yara: elem.Yara, Ioc: elem.Ioc, Index: elem.Index}
			tmpslice = append(tmpslice, resultStruct)

		}
		
		
		
		
		
	}

	sliceSet = tmpslice
}

func updateFirstResults() {
	var tmpslice []newResult
	var flagg bool
	for _, elem1 := range sliceNewResults {
		flagg = false
		for _, elem := range sliceSet {

			if elem1.Index == elem.Index {
				tmpslice = append(tmpslice, elem)
				flagg = true
			}
		}
		if flagg != true{
			
			tmpslice = append(tmpslice, elem1)
		}
	}

	sliceNewResults = tmpslice
}



func wordCount(str string) {

	wordList := strings.Fields(str)
	counts := make(map[string]int)
	for _, word := range wordList {
		_, ok := counts[word]
		if ok {
			counts[word] += 1
		} else {
			counts[word] = 1
		}

	}
	fmt.Println("Results")
	for index, elemn := range counts {
		fmt.Println("\t" + index + ":" + strconv.Itoa(elemn))
	}
	fmt.Println("\n")
}

func startHistory() {

	current_time := time.Now().Unix()
	historyFile = workspace + "/yaraRET_" + strconv.FormatInt(current_time, 10)
	fmt.Println("[+] Creating history file with name "+historyFile)
	os.Create(historyFile)

}

func saveCommand(command string) {

	f1, err := os.OpenFile(historyFile, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println(err)
	}
	f1.WriteString(command)
	f1.WriteString("\n")

}


func runMagicFooter(rawdisk string) uint64 {

	resultsMagic := searchYara(rawdisk, workspace+"/magicrules/magic_footer.yar")
	for _, elem := range resultsMagic {
		return elem.offset
	}
	fmt.Println(resultsMagic)
	return 0
}










func setBoot(rawdisk string) {
	var tmpslice []newResult
	resultsYara := searchYara(rawdisk, workspace+"/magicrules/boot.yar")
	
	for index, elem := range resultsYara {
		if index == 1 {
			resultStruct := newResult{Rule: "boot", Index: 99999, OffsetHeader: 0, OffsetFooter: elem.offset, Size: elem.offset}
			
			tmpslice = append(tmpslice, resultStruct)
			dumpRadareFooter(rawdisk, 0, elem.offset, elem.rule, "99999")
			sliceSet = tmpslice
			updateFirstResults()
		}
	}
}

func handlePEFooter() {
	var tmpslice []newResult
	fmt.Println(rawdisk)
	for _, elem := range sliceSet {
		if elem.Rule == "pe" {
			dumpRadare(totrawdisk, strconv.Itoa(int(elem.OffsetHeader)), elem.Rule, strconv.Itoa(elem.Index))
			realSize := getSizePe(elem.Rule + "_" + strconv.Itoa(elem.Index))
			resultStruct := newResult{Rule: elem.Rule, OffsetHeader: elem.OffsetHeader, OffsetFooter: elem.OffsetHeader + uint64(realSize), Data: elem.Data, Yara: elem.Yara, Ioc: elem.Ioc, Index: elem.Index, Hash: elem.Hash, Size: uint64(realSize), Ssdeep: elem.Ssdeep}
			tmpslice = append(tmpslice, resultStruct)
			var _, err = os.Stat(workspace + "/" + elem.Rule + "_" + strconv.Itoa(elem.Index))

			
			if os.IsNotExist(err) {
			} else {
				os.Remove(workspace + "/" + elem.Rule + "_" + strconv.Itoa(elem.Index))
			}
			fmt.Println(realSize)
		}
		sliceSet = tmpslice
		updateFirstResults()
	}

}

func getSizePe(file string) uint32 {

	f, err := pe.Open(file)
	if err != nil {
		
		maxsize64, err := strconv.ParseUint(maxSizeDump, 10, 32)
		if err != nil {
			print("ERROR: ", err)
		}
		return uint32(maxsize64)
	} else {
		fmt.Println(err)
		defer f.Close()
		size := f.FileHeader.SizeOfOptionalHeader
		var size2 uint32

		for _, s := range f.Sections {
			size2 += s.Size

		}

		sizeTot := size2 + uint32(size)

		return sizeTot
	}
}

func setFooterSupport() {

	

	b, err := ioutil.ReadFile(workspace + "/magicrules/magicrules_index.yar") 
	if err != nil {
		fmt.Print(err)
	}

	str := string(b) 
	list := strings.Split(str, "\n")

	for _, elem := range list {

		if strings.Contains(elem, "footer") {
			f := strings.Split(elem, "\"")[1]
			g := strings.Split(f, "_")[0]

			footersupport = append(footersupport, g)

		}
	}
}

func setHeaderSupport() {

	

	b, err := ioutil.ReadFile(workspace + "/magicrules/magicrules_index.yar") 
	if err != nil {
		fmt.Print(err)
	}

	str := string(b) 
	list := strings.Split(str, "\n")

	for _, elem := range list {

		if strings.Contains(elem, "header") {
			f := strings.Split(elem, "\"")[1]
			g := strings.Split(f, "_")[0]

			headersupport = append(headersupport, g)

		}
	}
}

func handleBMPFooter() {
	var tmpslice []newResult
	for _, elem := range sliceSet {
		rawdisk = totrawdisk
		if elem.Rule == "bmp" {
			dumpRadare(rawdisk, strconv.Itoa(int(elem.OffsetHeader)), elem.Rule, strconv.Itoa(elem.Index))
			realSize := getSizeBMP(elem.Rule + "_" + strconv.Itoa(elem.Index))
			resultStruct := newResult{Rule: elem.Rule, OffsetHeader: elem.OffsetHeader, OffsetFooter: elem.OffsetHeader + uint64(realSize), Data: elem.Data, Yara: elem.Yara, Ioc: elem.Ioc, Index: elem.Index, Hash: elem.Hash, Size: uint64(realSize), Ssdeep: elem.Ssdeep}
			tmpslice = append(tmpslice, resultStruct)
			var _, err = os.Stat(workspace + "/" + elem.Rule + "_" + strconv.Itoa(elem.Index))

			
			if os.IsNotExist(err) {
			} else {
				os.Remove(workspace + "/" + elem.Rule + "_" + strconv.Itoa(elem.Index))
			}
		}
		sliceSet = tmpslice
		updateFirstResults()
	}
}

func getSizeBMP(rawdisk string) uint32 {

	var hex string
	r2p, err := r2pipe.NewPipe(rawdisk)
	if err != nil {
		print("ERROR: ", err)
	}

	disasm, err := r2p.Cmd("b 1")
	if err != nil {
		print("ERROR: ", err)
	} else {
		print(disasm, "")
	}
	disasm, err = r2p.Cmd("s 0x0")
	if err != nil {
		print("ERROR: ", err)
	} else {
		print(disasm, "")
	}
	disasm2, err := r2p.Cmd("s 6")
	if err != nil {
		print("ERROR: ", err)
	} else {
		print(disasm2, "")
	}
	disasm99, err := r2p.Cmd("p8")
	if err != nil {
		print("ERROR: ", err)
	} else {
		print(disasm, "")
	}
	disasm2, err = r2p.Cmd("s -1")
	if err != nil {
		print("ERROR: ", err)
	} else {
		print(disasm, "")
	}
	disasm98, err := r2p.Cmd("p8")
	if err != nil {
		print("ERROR: ", err)
	} else {
		print(disasm, "")
	}
	disasm2, err = r2p.Cmd("s -1")
	if err != nil {
		print("ERROR: ", err)
	} else {
		print(disasm, "")
	}
	disasm97, err := r2p.Cmd("p8")
	if err != nil {
		print("ERROR: ", err)
	} else {
		print(disasm, "")
	}
	disasm2, err = r2p.Cmd("s -1")
	if err != nil {
		print("ERROR: ", err)
	} else {
		print(disasm, "")
	}
	disasm96, err := r2p.Cmd("p8")
	if err != nil {
		print("ERROR: ", err)
	} else {
		print(disasm, "")
	}
	hex = disasm98 + disasm99 + disasm96 + disasm97
	disasm3, err := r2p.Cmd("? 0x" + hex + "~int32[1]")
	if err != nil {
		print("ERROR: ", err)
	} else {
		i, err := strconv.ParseUint(disasm3, 10, 64)
		if err == nil {
			fmt.Println(i)
		}
		r2p.Close()
		return uint32(i)
	}
	r2p.Close()
	return (0)
}

func yaraLightCmd(argument []string, rawdisk string) {
	var tmpslice []newResult
	var rulesIn []string
	var _, err = os.Stat(argument[0])
	
	if os.IsNotExist(err) {
		fmt.Println("[-] Please, set a valid yara rule")
	} else {
		resultsYara := searchYara(rawdisk, argument[0])
		if len(resultsYara)>0{
			fmt.Println("[+] Results found!")
			for _, elem := range sliceSet {
				for _, elem1 := range resultsYara {
					if stringInSlice(elem1.rule, rulesIn) == false {
						if elem1.offset > elem.OffsetHeader && elem1.offset < elem.OffsetFooter {
							rulesIn = append(rulesIn, elem1.rule)
							fmt.Println("  [-] " + elem1.rule + " at " + elem.Rule + "_" + strconv.Itoa(elem.Index))
						}
					}
				}
				resultStruct := newResult{Rule: elem.Rule, OffsetHeader: elem.OffsetHeader, OffsetFooter: elem.OffsetFooter, Data: elem.Data, Yara: rulesIn, Ioc: elem.Ioc, Index: elem.Index, Hash: elem.Hash, Size: elem.Size, Ssdeep: elem.Ssdeep}
				tmpslice = append(tmpslice, resultStruct)
				rulesIn = nil
			}
			sliceSet = tmpslice
			updateFirstResults()
		}
	}
}

func handleNextOffset(tmpslice []newResult) []newResult {
	var tmpslice2 []newResult
	for index, elem := range tmpslice {
		fmt.Println(index)
		fmt.Println(elem)
		
		
		
		
		
		
	}

	return tmpslice2
}

func setFile(sliceSet []newResult, argument string) {
	rawdisk = totrawdisk
	if debug {
		fmt.Println(rawdisk)
		fmt.Println(argument)
	}
	for _, elem := range sliceSet {
		if strconv.Itoa(elem.Index) == argument {
			dumpRadare(rawdisk, strconv.Itoa(int(elem.OffsetHeader)), elem.Rule, strconv.Itoa(elem.Index))
			
		}
	}

}

func uniqPE() {
	var tmpslice []newResult

	rawdisk = totrawdisk
	for _, elem := range sliceSet {
		dumpRadare(rawdisk, strconv.Itoa(int(elem.OffsetHeader)), elem.Rule, strconv.Itoa(elem.Index))

		fmt.Println("Estoy en uniqPE")
		realSize := getSizePe(workspace + "/" + elem.Rule + "_" + strconv.Itoa(elem.Index))
		
		resultStruct := newResult{Rule: elem.Rule, OffsetHeader: elem.OffsetHeader, OffsetFooter: elem.OffsetHeader + uint64(realSize), Data: elem.Data, Yara: elem.Yara, Ioc: elem.Ioc, Index: elem.Index, Hash: elem.Hash, Size: uint64(realSize), Ssdeep: elem.Ssdeep}
		tmpslice = append(tmpslice, resultStruct)

	}
	sliceSet = tmpslice
}


func dumpCmd(rawdisk string) {

	for _, elem := range sliceSet {
		dumpRadareFooter(rawdisk, elem.OffsetHeader, elem.OffsetFooter, elem.Rule, strconv.Itoa(elem.Index))
		fmt.Println("[+] File Dumpled! " + elem.Rule + "_" + strconv.Itoa(elem.Index))

	}
}

func setFooterMaxSize() {
	var tmpslice []newResult
	maxsize64, err := strconv.ParseUint(maxSizeDump, 10, 32)
	if err != nil {
		print("ERROR: ", err)
	}
	for _, elem := range sliceSet {
		resultStruct := newResult{Rule: elem.Rule, OffsetHeader: elem.OffsetHeader, OffsetFooter: elem.OffsetHeader + uint64(maxsize64), Data: elem.Data, Yara: elem.Yara, Ioc: elem.Ioc, Index: elem.Index, Hash: elem.Hash, Size: maxsize64, Ssdeep: elem.Ssdeep}
		tmpslice = append(tmpslice, resultStruct)
	}
	sliceSet = tmpslice
}

func multPE(rawdisk string) {

	var tmpslice []newResult

	
	

	var myargument []string

	for _, elem := range sliceSet {
		dumpRadare(rawdisk, strconv.Itoa(int(elem.OffsetHeader)), elem.Rule, strconv.Itoa(elem.Index))
		
		myargument = append(myargument, strconv.Itoa(elem.Index))
		set2Cmd(myargument, rawdisk)
		myargument = nil

		realSize := getSizePe(workspace + "/" + elem.Rule + "_" + strconv.Itoa(elem.Index))
		os.Remove(workspace + "/" + elem.Rule + "_" + strconv.Itoa(elem.Index))
		os.Remove(workspace + "/tmp")
		resultStruct := newResult{Rule: elem.Rule, OffsetHeader: elem.OffsetHeader, OffsetFooter: elem.OffsetHeader + uint64(realSize), Data: elem.Data, Yara: elem.Yara, Ioc: elem.Ioc, Index: elem.Index, Hash: elem.Hash, Size: uint64(realSize), Ssdeep: elem.Ssdeep}
		tmpslice = append(tmpslice, resultStruct)
		}
		//fmt.Println(tmpslice)		
		sliceSet = tmpslice
		updateFirstResults()


}



func uploadCmd(argument []string, rawdisk string) {

	if len(argument)>0{
		host := argument[0]
		port := argument[1]
		for _, elem := range sliceSet {
			uploadRadare(rawdisk, strconv.Itoa(int(elem.OffsetHeader)), strconv.Itoa(int(elem.Size)), host, port)
			fmt.Println("[+]File uploaded!")

			
		}
	}else{
		fmt.Println("[!] Please, set the host and the port of the server")
	}
}




func lastItemStruct() {
	var tmpslice []newResult
	for item, elem := range sliceSet {

		if (item + 1) < len(sliceSet) {
			if (sliceSet[item+1].OffsetHeader) < elem.OffsetFooter {
				resultStruct := newResult{Rule: elem.Rule, OffsetHeader: elem.OffsetHeader, OffsetFooter: sliceSet[item+1].OffsetHeader - 1, Data: elem.Data, Yara: elem.Yara, Ioc: elem.Ioc, Index: elem.Index, Hash: elem.Hash, Size: elem.Size}
				tmpslice = append(tmpslice, resultStruct)
			} else {
				resultStruct := newResult{Rule: elem.Rule, OffsetHeader: elem.OffsetHeader, OffsetFooter: sliceSet[item+1].OffsetHeader - 1, Data: elem.Data, Yara: elem.Yara, Ioc: elem.Ioc, Index: elem.Index, Hash: elem.Hash, Size: elem.Size}
				tmpslice = append(tmpslice, resultStruct)
			}

		}
	}
	sliceSet = tmpslice
}




func putTag(argument string){

	var tmpslice []newResult

	for _, elem := range sliceSet{
		resultStruct := newResult{Rule: elem.Rule, OffsetHeader: elem.OffsetHeader, OffsetFooter: elem.OffsetFooter, Data: elem.Data, Yara: elem.Yara, Ioc: elem.Ioc, Index: elem.Index, Hash: elem.Hash, Size: elem.Size, Ssdeep: elem.Ssdeep, Tag: argument}									
		tmpslice = append(tmpslice, resultStruct)
		
	}
	sliceSet = tmpslice
}
		
