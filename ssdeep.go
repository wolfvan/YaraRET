package main

import (
	"fmt"
	//      "encoding/gob"
	//      "net"

	"github.com/glaslos/ssdeep"
	"strconv"
	"os"


)

func checkSsdeep(rawdisk string) {
	var nameFile string

	var tmpsliceIOC []newResult

	for _, elem := range sliceSet {
		//fmt.Println(sliceSet)

		if elem.OffsetFooter == 0 {
			fmt.Println("[-] Please, set footer before running ssdeep")

			//fmt.Println(rawdisk)
		} else {
			nameFile = elem.Rule + "_" + strconv.Itoa(elem.Index)
			var _, err = os.Stat(workspace + "/" + nameFile)

			if os.IsNotExist(err) {
				dumpRadareFooter(rawdisk, elem.OffsetHeader, elem.OffsetFooter+uint64(len(elem.Data)), elem.Rule, strconv.Itoa(elem.Index))
			}
			h1, err := ssdeep.FuzzyFilename(rawdisk)
			if err != nil && !ssdeep.Force {
				fmt.Println(err)
				os.Exit(1)
			}
			os.Remove(workspace + "/" + elem.Rule + "_" + strconv.Itoa(elem.Index))
			resultStruct := newResult{Rule: elem.Rule, OffsetHeader: elem.OffsetHeader, OffsetFooter: elem.OffsetFooter, Data: elem.Data, Yara: elem.Yara, Ioc: elem.Ioc, Index: elem.Index, Hash: elem.Hash, Size: elem.Size, Ssdeep: h1}
			tmpsliceIOC = append(tmpsliceIOC, resultStruct)
			}

			}

		sliceSet = tmpsliceIOC
		updateFirstResults()
					



}

func checkEverySsdeep(elem newResult) string {
	rawdisk = totrawdisk
	if elem.OffsetFooter == 0 {
		dumpRadare(rawdisk, strconv.Itoa(int(elem.OffsetHeader)), elem.Rule, strconv.Itoa(elem.Index))
		rawdisk = elem.Rule + "_" + strconv.Itoa(elem.Index)

		//fmt.Println(rawdisk)
	} else {
		dumpRadareFooter(rawdisk, elem.OffsetHeader, elem.OffsetFooter+uint64(len(elem.Data)), elem.Rule, strconv.Itoa(elem.Index))
		rawdisk = elem.Rule + "_" + strconv.Itoa(elem.Index)
	}
	h1, err := ssdeep.FuzzyFilename(rawdisk)
	if err != nil && !ssdeep.Force {
		fmt.Println(err)
		os.Exit(1)
	}
	os.Remove(workspace + "/" + rawdisk)
	return h1

}

func checkSsdeepDistance(ssdeep1 string, file string) int {

	var score int
	ssdeep2, err := ssdeep.FuzzyFilename(file)
	if err != nil && !ssdeep.Force {
		fmt.Println(err)
		os.Exit(1)
	}
	//fmt.Println(ssdeep1)
	score, err = ssdeep.Distance(ssdeep1, ssdeep2)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	return score

}