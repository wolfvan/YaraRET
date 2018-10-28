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
	//      "encoding/gob"
	//      "net"
	"bufio"
	"sort"
	"strconv"
	"log"
	"strings"
	"os"
    yara "github.com/hillu/go-yara"
)


func extractFromYara(rawdisk string, yarafile string, maxsize string, filetype string) {
	//var v []result
	var offsetExtracted []string
	count := 0
	count2 := 0
	//supported := []string{"threegp","sevenzip","amazonkindleupdate","appleworks5","appleworks6","avi","bmp","bzip","canonraw","crx","dalvik","dat","dba","deb","dmg","doc","elf64","flac","flash","gif","gzip","is","javaclass","jpg","kodakcineon","macho","microsoftOffice","midi","mkv","mp3","mpeg","ost","pcap","pcapng","pdf","pe","png","pds","pst","pyc","rar","rpm","rtf","tape","tar","tarzip","tiff","utf8","vmdk","wasm","wav","woff","xar","xml","xz","zip","zlib"}
	fmt.Println("[+] Running Yara..")
	resultsToT := searchYara(rawdisk, yarafile)

	maxsizeInt, err := strconv.ParseFloat(maxsize, 64)
	if err != nil {
		fmt.Println(err)
	}

	if len(resultsToT)==0{

		fmt.Println("[!] Not results found")
	}else{
		
		fmt.Println("[+] " + strconv.Itoa(len(resultsToT)) + " match found")
		fmt.Println("[-] Looking for magic numbers")
		resultsMagic := findAllData(rawdisk)

		for _, result := range resultsToT{
			count2 = count2 +1
			fmt.Println("[-] Looking for magic around "+result.rule+"_"+strconv.Itoa(count2))

			top := result.offset - uint64(maxsizeInt)

			for _, magic := range resultsMagic{
				if magic.offset > top {
					if magic.offset < result.offset{
						if stringInSlice(strconv.Itoa(int(magic.offset)), offsetExtracted){
						}else{
							count = count +1 
							dumpRadareFooter(rawdisk, magic.offset, magic.offset+2*uint64(maxsizeInt), strings.Split(result.rule, "_")[0], strconv.Itoa(count))
							fmt.Println("[+] Dumped file:\n\t[-] Rule: " + strings.Split(result.rule, "_")[0] + "\n\t[-] Name: " + result.rule + "\n\t[-] FileType: " + strings.Split(magic.rule, "_")[0])
							offsetExtracted = append(offsetExtracted, strconv.Itoa(int(magic.offset)))	
							}
					}
				}

			}
		}



	}

}



func searchYara(rawdisk string, yarafile string) []result {

	var v []result
	//var sortResult []result
	comp, err := yara.NewCompiler()
	f, err := os.Open(yarafile)
	if err != nil {
		log.Fatalf("Could not open rule file: %s", err)
	}
	comp.AddFile(f, "")
	rules, err := comp.GetRules()
	if err != nil {
		//log.Fatalf("Failed to initialize YARA compiler: %s", err)
		fmt.Println(err)
	}

	matches, err := rules.ScanFile(rawdisk, 0, 0)
	if err != nil {
		//fmt.Println("Error en el compilador")
		fmt.Println(err)
	}

	for _, matches := range matches {
		for _, stringf := range matches.Strings {
			s := result{rule: matches.Rule, offset: stringf.Offset, Data: stringf.Data}
			v = append(v, s)
			//fmt.Println(s)
			//fmt.Println("[+] Match! "+s.rule)
		}
	}
	//sortResult :=sortResultsByOffset(v)
	//fmt.Println(v)
	//sort.Sort
	sort.Sort(offsetSorter(v))
	//sortResult =sort.Sort(offsetSorter(v))
	//fmt.Println(v)
	return v

}



func runHash(rawdisk string, filetype string, hashes string) {

	var tmpslice []newResult
	var count int

	yarafileHeader := workspace + "/magicrules/" + filetype + "_header.yar"
	yarafileFooter := workspace + "/magicrules/" + filetype + "_footer.yar"
	//var lastResult result

	//var newR newResult

	resultsHash := searchYara(rawdisk, yarafileHeader)
	resultsHash2 := searchYara(rawdisk, yarafileFooter)

	sliceNewResults := generateNewResult(resultsHash)

	for index, elem := range sliceNewResults {
		count = count + 1
		result := newResult{Rule: elem.Rule, OffsetHeader: sliceNewResults[index].OffsetHeader, OffsetFooter: resultsHash2[index].offset + uint64(len(resultsHash2[index].Data)-1), Index: elem.Index}
		tmpslice = append(tmpslice, result)

	}

	//fmt.Println("[+] "+strconv.Itoa(count)+" "+filetype+" found")

	file, err := os.Open(hashes)
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

	for _, elem3 := range tmpslice {

		//fmt.Println("[+] Header "+strconv.Itoa(int(elem3.OffsetHeader))+" Offset:"+strconv.Itoa(int(elem3.OffsetFooter))+" :")
		hashTmp := getHashReturn(rawdisk, elem3.OffsetHeader, elem3.OffsetFooter)
		for _, elem5 := range lines {
			if elem5 == hashTmp {
				fmt.Println("[+] Match " + elem5 + " at " + strconv.Itoa(int(elem3.OffsetHeader)))
			}

		}
	}

	//fmt.Println(resultsHash)

	//fmt.Println(sliceNewResults)

}


func buildRuleOneliner(offset1 string, offset2 string, filetype string) string{
	body := returnBody(filetype)
	body1 := strings.Replace(body,"COUNT",offset1,-1)
	//fmt.Println(body1)
	condition := returnCondition(offset1, offset2)
	//fmt.Println(condition)
	rule := body1+condition
	
	return rule

}