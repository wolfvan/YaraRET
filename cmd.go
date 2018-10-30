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
	
	
	"github.com/radare/r2pipe-go"
	"encoding/json"
	"log"
    "github.com/dutchcoders/go-virustotal"
	"io/ioutil"
	"strconv"
	"strings"
	"os"
)

var debug bool

func startCmd(arguments []string, rawdisk string) {

	supported := []string{"threegp","sevenzip","amazonkindleupdate","appleworks5","appleworks6","avi","bmp","bzip","canonraw","crx","dalvik","dat","dba","deb","dmg","doc","elf64","flac","flash","gif","gzip","is","javaclass","jpg","kodakcineon","macho","mft","microsoftOffice","midi","mkv","mp3","mpeg","ost","pcap","pcapng","pdf","pe","png","pds","pst","pyc","rar","rpm","rtf","tape","tar","tarzip","tiff","utf8","vmdk","wasm","wav","woff","xar","xml","xz","zip","zlib"}


	if arguments[0] == "all" {


		fmt.Println("[+] Searching for headers")
		resultsMagic := findAllData(rawdisk)
		
		resultsMagicINIT = resultsMagic
		
		fmt.Println("[+] Generating results")
		sliceNewResults = generateNewResult(resultsMagic)
		
		
		
		
		fmt.Println("[+] Generating data")
		fmt.Println("\n")
		var allRules string
		for _, element := range sliceNewResults {
			allRules = allRules + element.Rule + " "

		}
		wordCount(allRules)
		sliceSet = sliceNewResults

	}else{ 
		
		if stringInSlice(arguments[0], supported){
			resultsFiletype:=findOneData(rawdisk, arguments[0])
			sliceNewResults = generateNewResult(resultsFiletype)
			sliceSet = sliceNewResults
			var allRules string
			for _, element := range sliceNewResults {
				allRules = allRules + element.Rule + " "

			}
			wordCount(allRules)
			dataSelected = arguments[0]						
		}else{
			fmt.Println("[-] This filetype is not supported")
		}
	}
}

func unsetCmd(arguments []string, rawdisk string) {

	var v []newResult
	totIndex = arguments[0]

	if arguments[0] == "yara" {
		unsetSliceYara(arguments[1])
	}

	if _, err := strconv.Atoi(arguments[0]); err == nil {

		for _, elem := range sliceSet {
			if arguments[0] == strconv.Itoa(elem.Index) {
			} else {
				v = append(v, elem)
			}
			sliceSet = v
		}
	} else {
		for _, elem := range sliceSet {
			if arguments[0] == elem.Rule {
			} else {
				v = append(v, elem)
			}
			sliceSet = v
		}
	}

}

func saveCmd(arguments []string, rawdisk string) {
	last := false
	count := 0
	if len(OutputFile) == 0 {
		fmt.Println("[-] You don't have set an output file, please, set it with output <fileName>")
	} else {
		f1, err := os.OpenFile(OutputFile, os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Println("err")
		}
		f1.WriteString("[")
		f1.Close()
		for _, elem := range sliceNewResults {
			count = count+1
			myJson := &newResult{Rule: elem.Rule, OffsetHeader: elem.OffsetHeader, OffsetFooter: elem.OffsetFooter, Data: elem.Data, Yara: elem.Yara, Ioc: elem.Ioc, Index: elem.Index, Ssdeep: elem.Ssdeep, Hash: elem.Hash, Size: elem.Size, Comment: elem.Comment}
			b, err := json.Marshal(myJson)

			if err != nil {
				fmt.Println(err)
				return
			}


			f, err := os.OpenFile(OutputFile, os.O_APPEND|os.O_WRONLY, 0600)
			if err != nil {
			    panic(err)
			}


			if _, err = f.WriteString(string(b)); err != nil {
			    panic(err)
			}

			if count == len(sliceNewResults){
				last = true
			}

			if last {

			}else{
				if _, err = f.WriteString(","); err != nil {
				    panic(err)
				}							

				}
			f.Close()
		}
		fmt.Println(count)
		fmt.Println(len(sliceNewResults))

		f, err := os.OpenFile(OutputFile, os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
		    panic(err)
		}
		if _, err = f.WriteString("]"); err != nil {
		    panic(err)
		}		
		f.Close()		

	
		fmt.Println("[+] Saved as " + OutputFile)		
	}

}

func openCmd(argument []string, rawdisk string) {

	
	
	
	var myOwnResults []newResult
	
	
	
	
	
	
	
	
	file, e := ioutil.ReadFile(workspace + "/" + argument[0])

	if e != nil {
		fmt.Printf("File error: %v\n", e)
		os.Exit(1)
	}

	json.Unmarshal(file, &myOwnResults)
	
	var allRules string
	for _, element := range myOwnResults {
		allRules = allRules + element.Rule + " "

	}
	wordCount(allRules)
	
	sliceNewResults = myOwnResults

}

func vtiCmd(argument []string, rawdisk string) {

	if len(vtiAPI) < 4 {
		fmt.Println("Please set the API key")
	} else {
		apikey := vtiAPI
		

		if len(argument) > 0 {
			vt, err := virustotal.NewVirusTotal(apikey)
			if err != nil {
				log.Fatal(err)
			}

			switch option := argument[0]; option {
			case "scan":
				var result *virustotal.ScanResponse

				
				for _, elem := range sliceSet {
					fmt.Printf("Uploading %s to VirusTotal: ", (elem.Rule + "_" + strconv.Itoa(elem.Index)))

					file, err := os.Open((elem.Rule + "_" + strconv.Itoa(elem.Index)))

					if err != nil {
						log.Fatal(err)
					}

					defer file.Close()

					result, err = vt.Scan((elem.Rule + "_" + strconv.Itoa(elem.Index)), file)

					if err != nil {
						log.Fatal(err)
					}

					fmt.Printf("%s\n", result)

				}


			case "report":
				for _, elem := range sliceSet {
					fmt.Println("[+] Checking for this: "+elem.Hash)

					result, err := vt.Report(elem.Hash)

					if err != nil {
						log.Fatal(err)
					}

					fmt.Printf("%s\n", result)

			}
			default:
				fmt.Println("Usage:")
				fmt.Println("")
				fmt.Println("go run ./bin/vt.go --apikey {key} (--debug) scan {file} {file} ..")
				fmt.Println("go run ./bin/vt.go --apikey {key} (--debug) rescan {hash} {hash} ..")
				fmt.Println("go run ./bin/vt.go --apikey {key} (--debug) report 99017f6eebbac24f351415dd410d522d")
				fmt.Println("go run ./bin/vt.go --apikey {key} (--debug) scan-url {url} {url} ..")
				fmt.Println("go run ./bin/vt.go --apikey {key} (--debug) report-url www.google.com")
				fmt.Println("go run ./bin/vt.go --apikey {key} (--debug) ipaddress 90.156.201.27")
				fmt.Println("go run ./bin/vt.go --apikey {key} (--debug) domain 027.ru")
				fmt.Println("go run ./bin/vt.go --apikey {key} (--debug) --resource 99017f6eebbac24f351415dd410d522d comment \"How to disinfect you from this file.. #disinfect #zbot\"")

			}

		}
	}

}

func showCmd(argument []string, rawdisk string) {

	var rulesStr string

	switch option := argument[0]; option {
	case "-":
		for _, elem := range sliceSet {

			fmt.Println("File:" + elem.Rule)
			fmt.Println("\tIndex:" + strconv.Itoa(elem.Index))
			fmt.Println("\tOffset Header:" + strconv.Itoa(int(elem.OffsetHeader)))
			fmt.Println("\tOffset Footer:" + strconv.Itoa(int(elem.OffsetFooter)))
			if len(elem.Yara) > 0 {
				for _, elem1 := range elem.Yara {
					rulesStr = rulesStr + " " + elem1
				}
				fmt.Println("\tYara:" + rulesStr)
				rulesStr = ""
			}

			if len(elem.Ssdeep) > 0 {
				fmt.Println("\tSSDeep:" + elem.Ssdeep)

			}

			if len(elem.Hash) > 0 {
				fmt.Println("\tHash:" + elem.Hash)

			}

			if len(elem.Comment) > 0 {
				fmt.Println("\tComments:" + elem.Comment)

			}

			if elem.OffsetFooter > 0 {
				fmt.Println("\tSize:" + strconv.Itoa(int(elem.Size)))

			}
			if len(elem.Tag) > 0 {
				fmt.Println("\tTag:" + elem.Tag)

			}
			if elem.Entropy > 0 {
				fmt.Println("\tEntropy:" +  strconv.Itoa(int(elem.Entropy)))

			}							
			fmt.Println("\n") 
			
		}

	case "all":

		for _, elem := range sliceNewResults {
			fmt.Println("File:" + elem.Rule)
			fmt.Println("\tIndex:" + strconv.Itoa(elem.Index))
			fmt.Println("\tOffset Header:" + strconv.Itoa(int(elem.OffsetHeader)))
			fmt.Println("\tOffset Footer:" + strconv.Itoa(int(elem.OffsetFooter)))
			if len(elem.Yara) > 0 {
				fmt.Println("\tYara:\n")
				fmt.Println(elem.Yara)

			}

			if len(elem.Ssdeep) > 0 {
				fmt.Println("\tSSDeep:" + elem.Ssdeep)

			}
			fmt.Println("\n")
		}

	case "support":
		if argument[0] == "support" {
			fmt.Println("[-]Header Support:")
			for _, elem := range headersupport {
				fmt.Println("\t" + elem)
			}
			fmt.Println("\n[-]Footer Support:")
			for _, elem2 := range footersupport {
				fmt.Println("\t" + elem2)
			}
		}
	case "info":
		var allRules string
		if debug {
			fmt.Println("[*] Into stats")
		}
		for _, element := range sliceSet {
			allRules = allRules + element.Rule + " "

		}
		wordCount(allRules)
	default:
		for _, elem := range sliceSet {
			if strings.Contains(elem.Rule, option) {
				fmt.Println("File:" + elem.Rule)
				fmt.Println("\tIndex:" + strconv.Itoa(elem.Index))
				fmt.Println("\tOffset Header:" + strconv.Itoa(int(elem.OffsetHeader)))
				fmt.Println("\tOffset Footer:" + strconv.Itoa(int(elem.OffsetFooter)))
				if len(elem.Yara) > 0 {
					for _, elem1 := range elem.Yara {
						rulesStr = rulesStr + " " + elem1
					}
					fmt.Println("\tYara:" + rulesStr)
					rulesStr = ""
				}

				if len(elem.Ssdeep) > 0 {
					fmt.Println("\tSSDeep:" + elem.Ssdeep)

				}

				if len(elem.Hash) > 0 {
					fmt.Println("\tHash:" + elem.Hash)

				}

				if len(elem.Comment) > 0 {
					fmt.Println("\tComments:" + elem.Comment)

				}

				if elem.OffsetFooter > 0 {
					fmt.Println("\tSize:" + strconv.Itoa(int(elem.Size)))

				}
				fmt.Println("\n") 
				
			}
		}

	}

}


func footerCmd(argument []string, rawdisk string) {
	
	fmt.Println(dataSelected)



}




func set2Cmd(argument []string, rawdisk string) {

	maxsize64, err := strconv.ParseUint(maxSizeDump, 10, 32)
	if err != nil {
		print("ERROR: ", err)
	}	
	var resultStruct newResult
	supportedFooter := []string{"pdf","jpg","gif","doc", "mft"}
	var tmpslice []newResult
	if _, err := strconv.Atoi(argument[0]); err == nil {

		for _, elem := range sliceSet{
			if argument[0] == strconv.Itoa(elem.Index) {
				tmpslice = append(tmpslice, elem)

			}
		}
		sliceSet = tmpslice
	}else{



		switch option := argument[0]; option {
		case "all":
			sliceSet = sliceNewResults
		case "yara":
 			setSliceYara(argument[1])
			updateFirstResults()
		case "entropy":
 			setSliceEntropy(argument[1:])
		case "footer":

			if len(argument)<2{

			flagg := false
			if dataSelected == "pe"{
				fmt.Println("[+] Setting a footer for pe")
				if len(sliceSet) < 2 {
					for _, elem:= range sliceSet{
						fmt.Println(rawdisk)
						dumpRadare(rawdisk, strconv.Itoa(int(elem.OffsetHeader)), elem.Rule, strconv.Itoa(elem.Index))
						uniqPE()
						updateFirstResults()
						
					}
				} else {
					multPE(rawdisk)
				}
			}else{
				if stringInSlice(dataSelected, supportedFooter){
					footers := findFooter(dataSelected,rawdisk)
					for _, elem:= range footers{
						for index2, elem2 := range sliceSet{
							if len(sliceSet)==1{
								if flagg == false{
									if elem.offset > elem2.OffsetHeader{
										resultStruct = newResult{Rule: elem2.Rule, OffsetHeader: elem2.OffsetHeader, OffsetFooter: elem.offset, Data: elem2.Data, Yara: elem2.Yara, Ioc: elem2.Ioc, Index: elem2.Index, Hash: elem2.Hash, Size: elem.offset-elem2.OffsetHeader, Ssdeep: elem2.Ssdeep}									
										tmpslice = append(tmpslice, resultStruct)
										flagg = true
										sliceSet = tmpslice
								}

								}
							}else{
								if index2 < len(sliceSet)-1{

									if elem.offset > elem2.OffsetHeader && elem.offset <sliceSet[index2+1].OffsetHeader{

										resultStruct = newResult{Rule: elem2.Rule, OffsetHeader: elem2.OffsetHeader, OffsetFooter: elem.offset, Data: elem2.Data, Yara: elem2.Yara, Ioc: elem2.Ioc, Index: elem2.Index, Hash: elem2.Hash, Size: elem.offset-elem2.OffsetHeader, Ssdeep: elem2.Ssdeep}
										tmpslice = append(tmpslice, resultStruct)
									
								}
								}
								
							}
						}
						
						
					}

				}else{
					fmt.Println("[!] This file does not have footer support\nPutting a generic footer")
					for _, elem2:= range sliceSet{
						resultStruct = newResult{Rule: elem2.Rule, OffsetHeader: elem2.OffsetHeader, OffsetFooter: elem2.OffsetHeader+maxsize64, Data: elem2.Data, Yara: elem2.Yara, Ioc: elem2.Ioc, Index: elem2.Index, Hash: elem2.Hash, Size: maxsize64, Ssdeep: elem2.Ssdeep}									
						tmpslice = append(tmpslice, resultStruct)
					}		
				}
			}
		}else{
			switch option2 := argument[1]; option2{
			case "generic":
				for _, elem3 := range sliceSet{
					resultStruct = newResult{Rule: elem3.Rule, OffsetHeader: elem3.OffsetHeader, OffsetFooter: elem3.OffsetHeader+maxsize64, Data: elem3.Data, Yara: elem3.Yara, Ioc: elem3.Ioc, Index: elem3.Index, Hash: elem3.Hash, Size: maxsize64, Ssdeep: elem3.Ssdeep}
					tmpslice = append(tmpslice, resultStruct)
				}
			sliceSet = tmpslice
			updateFirstResults()				
			}
		}


		case "maxsize":
			if len(argument)>1{
				maxSizeDump = argument[1]				
			}
		default:
			dataSelected = argument[0]
			setSlice(argument[0])			
		}
	}

	if len(tmpslice)>1{
		sliceSet = tmpslice
		updateFirstResults()					
	}

}


func outputCmd(argument []string, rawdisk string) {

	OutputFile = argument[0]
	
	f, err := os.Create(OutputFile)
	if err != nil {
		panic(err)
	}
	defer f.Close()

}

func hashCmd(argument []string, rawdisk string) {

	var tmpslice []newResult
	if len(argument) < 1 {

		for _, elem1 := range sliceSet {
			a := getHashSelected(rawdisk, elem1.OffsetHeader, elem1.Size)
			
			resultStruct := newResult{Rule: elem1.Rule, OffsetHeader: elem1.OffsetHeader, OffsetFooter: elem1.OffsetFooter, Data: elem1.Data, Yara: elem1.Yara, Ioc: elem1.Ioc, Index: elem1.Index, Hash: a, Size: (elem1.OffsetFooter - elem1.OffsetHeader)}
			tmpslice = append(tmpslice, resultStruct)
			
		}
	}
	sliceSet = tmpslice
	updateFirstResults()
	
	

}

func ssdeepCmd(argument []string, rawdisk string) {
	var tmpsliceIOC []newResult

	if len(argument) < 1 {
		checkSsdeep(rawdisk)
	} else {

		for _, elem := range sliceSet {
			ssdeep1 := checkEverySsdeep(elem)

			resultStruct := newResult{Rule: elem.Rule, OffsetHeader: elem.OffsetHeader, OffsetFooter: elem.OffsetFooter, Data: elem.Data, Yara: elem.Yara, Ioc: elem.Ioc, Index: elem.Index, Hash: elem.Hash, Size: elem.Size, Ssdeep: ssdeep1}

			tmpsliceIOC = append(tmpsliceIOC, resultStruct)
		}

		sliceSet = tmpsliceIOC
		
		updateFirstResults()
	}

	if len(argument) > 0 {
		if argument[0] == "path" {

			path := argument[1]
			var _, err = os.Stat(workspace + "/" + argument[1])

			
			if os.IsNotExist(err) {
			} else {
				files, err := ioutil.ReadDir(path)
				if err != nil {
					log.Fatal(err)
				}
				for _, j := range files {
					for _, elem2 := range sliceSet {
						score := checkSsdeepDistance(elem2.Ssdeep, path+j.Name())
						if score > 20 {
							fmt.Println("  [-] Match! - " + j.Name() + " with " + elem2.Rule + "_" + strconv.Itoa(elem2.Index) + " -  Score:" + strconv.Itoa(score))
						}
					}
				}
				

			}
		}
	}

}

func entropyCmd2(argument []string, rawdisk string) {
	var tmpsliceIOC []newResult


	for _, elem := range(sliceSet){
		fmt.Println("entrop a")
		valueInt := getEntropyValue(rawdisk, strconv.Itoa(int(elem.OffsetHeader)), strconv.Itoa(int(elem.Size)))
		resultStruct := newResult{Rule: elem.Rule, OffsetHeader: elem.OffsetHeader, OffsetFooter: elem.OffsetFooter, Data: elem.Data, Yara: elem.Yara, Ioc: elem.Ioc, Index: elem.Index, Hash: elem.Hash, Size: elem.Size, Ssdeep: elem.Ssdeep, Entropy: valueInt}
		tmpsliceIOC = append(tmpsliceIOC, resultStruct)

	}
	sliceSet = tmpsliceIOC
	updateFirstResults()
}


func getEntropyValue(rawdisk string, header string, size string) int64{
	var valueInt int64

	dumpRadare(rawdisk, header, "tmpentropy", "2")	
	

	r2p, err := r2pipe.NewPipe("./tmpentropy_2")
	if err != nil {
		print("ERROR: ", err)
	}
	defer r2p.Close()

	r2p.Cmd("b "+size)


	disasm, err := r2p.Cmd("p=e")
	if err != nil {
		print("ERROR: ", err)
	} else {
		if len(disasm)>1{
			value := strings.Split(disasm, " ")[2]
			valueInt, err = strconv.ParseInt(value, 16, 64)
			if err != nil {
				print("ERROR: ", err)
			}		
			
		}
	os.Remove(workspace + "/tmpentropy_2")
	os.Remove(workspace + "/tmp")	

	}
	r2p.Close()
	return valueInt


		

}




func entropyCmd(argument []string, rawdisk string) {

	r2p, err := r2pipe.NewPipe(rawdisk)
	if err != nil {
		print("ERROR: ", err)
	}
	defer r2p.Close()

	disasm, err := r2p.Cmd("b 2000")
	if err != nil {
		print("ERROR: ", err)
	} else {
		disasm := ""
		print(disasm, "")
	}

	disasm, err = r2p.Cmd("p=")
	if err != nil {
		print("ERROR: ", err)
	} else {
		disasm := ""
		print(disasm, "")
	}

	sliceDisas := strings.Split(disasm, "\n")
	for _, i := range sliceDisas {
		valueprev, err := strconv.ParseUint(strings.Split(i, " ")[2], 16, 64)
		if err != nil {
			print("ERROR: ", err)
		}
		
		if valueprev > 150 {
			fmt.Println("Abnormal value " + strconv.Itoa(int(valueprev)) + " at " + strings.Split(i, " ")[0])
		}
		
		

	}

}

func yaraforensicsCmd(argument []string, rawdisk string) {


	if _, err := os.Stat( workspace+"/yara-forensics/yara-forensics_index.yar"); err == nil {

		resultsMagic := searchYara(rawdisk, workspace+"/yara-forensics/yara-forensics_index.yar")
		
		sliceNewResults := generateNewResultYaraForensics(resultsMagic)

		fmt.Println("[+] Calculating data")
		var allRules string
		for _, element := range sliceNewResults {
			allRules = allRules + element.Rule + " "

		}
		wordCount(allRules)
		sliceSet = sliceNewResults
	}else{
		fmt.Println("[-] Please, build an index for rules in /yara-forensics/yara-forensics_index.yar")
	}
}

func runCmd(argument []string, rawdisk string) {
	script := argument[0]

	dat, err := ioutil.ReadFile(script)
	if err != nil {
		panic(err)
	}
	datSlice := strings.Split(string(dat), "\n")
	for _, elem := range datSlice {
		

		command := strings.Split(string(elem), " ")

		switch option := command[0]; option {
		case "start":
			startCmd(command[1:], rawdisk)

		case "set":
			set2Cmd(command[1:], rawdisk)
		case "yara":
			if command[1] == "+" {
				yaraCmd(command[1])
			} else {
				yaraLightCmd(command[1:], rawdisk)
			}
		case "hash":
			hashCmd(command[1:], rawdisk)
		case "ssdeep":
			ssdeepCmd(command[1:], rawdisk)
		case "save":
			saveCmd(command[1:], rawdisk)
		case "open":
			openCmd(command[1:], rawdisk)
		case "ioc":
			searchOpenIOCCmd2(rawdisk, command[1])
		case "vti":
			vtiCmd(command[1:], rawdisk)
		case "~":
			radareCmd(command[1:], rawdisk)
		case "show":
			showCmd(command[1:], rawdisk)
		case "unset":
			unsetCmd(command[1:], rawdisk)
		case "entropy":
			entropyCmd2(command[1:], rawdisk)			
		}
	}

}


func yaraCmd(argument string) {

	rawdisk = totrawdisk
	var tmpslice []newResult
	var rulesIn []string
	if _, err := os.Stat(argument); err == nil {
		fmt.Println("[+] Deep scanning for match")

		if len(sliceSet) < 2 {
			resultsYara := searchYara(rawdisk, argument)
			for _, elem := range resultsYara {
				fmt.Println("Rule:" + elem.rule)
				fmt.Println("Offset:" + strconv.Itoa(int(elem.offset)))
				fmt.Println("\n")
				updateResultsYara(resultsYara)
				updateFirstResults()
			}
		} else {
			
			firstRaw := rawdisk
			for _, elem := range sliceSet {
				rawdisk = firstRaw
				if elem.OffsetFooter == 0 {
					dumpRadare(rawdisk, strconv.Itoa(int(elem.OffsetHeader)), elem.Rule, strconv.Itoa(elem.Index))
					rawdisk = elem.Rule + "_" + strconv.Itoa(elem.Index)
					resultsYara := searchYara(rawdisk, argument)
					
					
					
					
					rulesIn = elem.Yara
					for _, elem1 := range resultsYara {
						if stringInSlice(elem1.rule, rulesIn) == false {

							rulesIn = append(rulesIn, elem1.rule)
							fmt.Println("\t[-] " + elem1.rule + " at " + elem.Rule + "_" + strconv.Itoa(elem.Index))
							
						}
					}

					resultStruct := newResult{Rule: elem.Rule, OffsetHeader: elem.OffsetHeader, OffsetFooter: elem.OffsetFooter, Data: elem.Data, Yara: rulesIn, Ioc: elem.Ioc, Index: elem.Index, Hash: elem.Hash, Size: elem.Size}
					tmpslice = append(tmpslice, resultStruct)
					rulesIn = nil

					var _, err = os.Stat(workspace + "/" + rawdisk)

					
					if os.IsNotExist(err) {
					} else {
						os.Remove(workspace + "/" + rawdisk)
					}

					
					

					
				} else {
					dumpRadareFooter(rawdisk, elem.OffsetHeader, elem.OffsetFooter+uint64(len(elem.Data)), elem.Rule, strconv.Itoa(elem.Index))
					rawdisk = elem.Rule + "_" + strconv.Itoa(elem.Index)
					resultsYara := searchYara(rawdisk, argument)
					rulesIn = elem.Yara
					for _, elem1 := range resultsYara {
						if stringInSlice(elem1.rule, rulesIn) == false {
							rulesIn = append(rulesIn, elem1.rule)
							
						}
					}
					resultStruct := newResult{Rule: elem.Rule, OffsetHeader: elem.OffsetHeader, OffsetFooter: elem.OffsetFooter, Data: elem.Data, Yara: rulesIn, Ioc: elem.Ioc, Index: elem.Index, Hash: elem.Hash, Size: elem.Size}
					tmpslice = append(tmpslice, resultStruct)
					rulesIn = nil

				}
				
				err := os.Remove(workspace + "/" + rawdisk)
				if err != nil {
					
				}
				
			}
			sliceSet = tmpslice
		}
		
		
		
		

		updateFirstResults()
		
		
		
		

		
		
		
		
		
		

		
		

		

		
		
	} else {
		fmt.Println("Yara rule does not exist")
	}
}
